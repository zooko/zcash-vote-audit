// src-tauri/src/main.rs

use std::collections::BTreeSet;

use anyhow::Result;
use bip0039::Mnemonic;
use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey},
    vote::{try_decrypt_ballot, validate_ballot, Ballot, BallotData, OrchardHash},
};
use pasta_curves::{group::ff::PrimeField, Fp};
use serde::Deserialize;
use zcash_vote::{
    address::VoteAddress,
    as_byte256,
    election::{Election, BALLOT_VK},
};

#[derive(Clone, Debug)]
struct Count(PreparedIncomingViewingKey, FullViewingKey, u64);

#[derive(Deserialize)]
struct ElectionInput {
    question: u32,
    topic: String,
    seed: String,
    url: String,
}

fn fmt(val: u64) -> String {
    fn decimals_for(whole: u64) -> u32 {
        if whole >= 100 { 0 }
        else if whole >= 10 { 1 }
        else if whole >= 1 { 3 }
        else { 5 }
    }

    let whole = val / 100_000_000;
    let decimals = decimals_for(whole);
    let divisor = 10u64.pow(8 - decimals);
    let rounded = ((val + divisor / 2) / divisor) * divisor;
    let whole = rounded / 100_000_000;
    let frac = rounded % 100_000_000;
    let decimals = decimals_for(whole);

    let s = whole.to_string();
    let separated: String = s
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("_");

    let frac_part = if decimals == 0 {
        String::new()
    } else {
        let frac_str = format!("{:08}", frac);
        let trimmed = frac_str[..decimals as usize].trim_end_matches('0');
        if trimmed.is_empty() {
            String::new()
        } else {
            format!(".{}", trimmed)
        }
    };

    format!("{:>10}{:<6}", separated, frac_part)
}

fn fmt2(val: u64) -> String {
    let whole = val / 100_000_000;
    let frac = val % 100_000_000;

    let s = whole.to_string();
    let whole_str: String = s
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("_");

    let f = format!("{:08}", frac);
    let frac_str: String = f
        .as_bytes()
        .chunks(3)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("_");

    format!("{}.{}", whole_str, frac_str)
}

async fn audit(url: &str, seed_phrase: &str) -> Result<()> {
    let id = url.rsplit('/').next().unwrap();
    let data_dir = format!("data/{}", id);

    let election: Election = serde_json::from_str(
        &std::fs::read_to_string(format!("{data_dir}/election.json"))?
    )?;

    let mnemonic = Mnemonic::from_phrase(seed_phrase)?;
    let seed = mnemonic.to_seed("vote");

    let mut counts = vec![];
    for (i, c) in election.candidates.iter().enumerate() {
        let sk = SpendingKey::from_zip32_seed(&seed, 133, i as u32).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let address = fvk.address_at(0u64, Scope::External);
        let vote_address = VoteAddress::decode(&c.address)?;
        if vote_address.0 != address {
            anyhow::bail!("Invalid address for choice #{i}");
        }
        let ivk = fvk.to_ivk(Scope::External);
        let pivk = PreparedIncomingViewingKey::new(&ivk);
        counts.push(Count(pivk, fvk, 0u64));
    }

    let mut candidate_nfs = vec![];
    let mut frontier = election.cmx_frontier.clone().unwrap();
    let mut cmx_roots = BTreeSet::<Fp>::new();
    cmx_roots.insert(Fp::from_repr(election.cmx.0).unwrap());
    let mut nfs = BTreeSet::<Fp>::new();

    let n: u32 = std::fs::read_to_string(format!("{data_dir}/num_ballots.txt"))?
        .trim()
        .parse()?;

    println!("  {} ballots to process", n);

    for i in 1..=n {
        let raw: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{data_dir}/ballot_{i}.json"))?
        )?;

        let ballot: Ballot = serde_json::from_value(raw)?;

        let BallotData {
            version,
            domain,
            actions,
            anchors,
        } = ballot.data.clone();

        if version != 1 {
            anyhow::bail!("Invalid version");
        }

        let domain = Fp::from_repr(as_byte256(&domain)).unwrap();
        if domain != election.domain() {}

        let nf = &anchors.nf;
        if nf != &election.nf.0 {
            anyhow::bail!("nf roots do not match");
        }

        let cmx = Fp::from_repr(as_byte256(&anchors.cmx)).unwrap();
        if !cmx_roots.contains(&cmx) {
            anyhow::bail!("cmx roots do not match");
        }

        for action in actions.iter() {
            let nf = Fp::from_repr(as_byte256(&action.nf)).unwrap();
            if nfs.contains(&nf) {
                anyhow::bail!("duplicate dnf");
            }
            nfs.insert(nf);
            frontier.append(OrchardHash(as_byte256(&action.cmx)));

            for (idx, c) in counts.iter_mut().enumerate() {
                if let Some(note) = try_decrypt_ballot(&c.0, action)? {
                    let candidate_nf = note.nullifier_domain(&c.1, domain);
                    candidate_nfs.push(Fp::from_repr(candidate_nf.to_bytes()).unwrap());
                    c.2 += note.value().inner();
                    println!(
                        "    Ballot {:>3}: {} ZEC -> {:>7}  ({:>21})",
                        i,
                        fmt(note.value().inner()),
                        election.candidates[idx].choice,
                        fmt2(note.value().inner())
                    );
                }
            }
        }

        cmx_roots.insert(Fp::from_repr(frontier.root()).unwrap());
        validate_ballot(ballot, election.signature_required, &BALLOT_VK)?;
    }

    // Check that candidate notes are unspent
    for dnf in candidate_nfs.iter() {
        if nfs.contains(dnf) {
            anyhow::bail!("candidate notes cannot be spent");
        }
    }

    // Print totals
    println!();
    println!("  TOTALS:");
    for (c, cc) in counts.iter().zip(election.candidates.iter()) {
        println!("    {:>20}: {} ZEC  ({})", cc.choice, fmt(c.2), fmt2(c.2));
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let elections: Vec<ElectionInput> =
        serde_json::from_str(ELECTIONS_JSON).expect("bad embedded JSON");

    for e in &elections {
        println!();
        println!("{}", "=".repeat(70));
        println!("Q{}: {}", e.question, e.topic);
        println!("{}", "=".repeat(70));

        match audit(&e.url, &e.seed).await {
            Ok(()) => println!("  ✓ verified"),
            Err(err) => println!("  ✗ ERROR: {}", err),
        }
    }
}

const ELECTIONS_JSON: &str = r#"[
  {
    "question": 1,
    "topic": "Zcash Shielded Assets (ZSAs)",
    "seed": "bleak oval budget link step again suggest shallow girl write daring stock indoor angry token flag shove dream gentle priority grunt champion antique disease",
    "url": "https://zecvote.zone/election/d7281580b01f8d1d056b52965397a63895ac491538d49ae9a9bbb4458271f701"
  },
  {
    "question": 2,
    "topic": "Network Sustainability Mechanism (NSM)",
    "seed": "stage employ tobacco during response copy candy tumble trash little able work drum opinion recall thought pole stay height tray foam outer cup tumble",
    "url": "https://zecvote.zone/election/8f01a2ca0af8e088637dfde26524180bcb48e5ed5f7fb6410cfe2a385b269706"
  },
  {
    "question": 3,
    "topic": "NSM: Burn Transaction Fees",
    "seed": "face merge metal climb flat question awful retreat lobster legal chronic rich hire february aisle whale absent beauty analyst zoo elder during auto pond",
    "url": "https://zecvote.zone/election/b4e3b9a1008483ea68d8fb2abb4f8e6987e870d20fca410f3edae8ca8362d00e"
  },
  {
    "question": 4,
    "topic": "Memo Bundles",
    "seed": "shield mother misery warm once pattern crime little trash hungry amount desk abuse useful case give owner knock divert company doctor example royal panther",
    "url": "https://zecvote.zone/election/626452804795e079e8a43cb42183a38c55ad45d59bfe30c90478d8c660452308"
  },
  {
    "question": 5,
    "topic": "Explicit Fees",
    "seed": "play away auction envelope update useless exclude rather finish two enough sail piece organ stumble infant idle front loud absurd supreme library charge trouble",
    "url": "https://zecvote.zone/election/e3ac5600cf85c4e2dd82e53cf9f05975052a9779325c0e43305b6ab7cb592101"
  },
  {
    "question": 6,
    "topic": "V4 Transactions / Sprout",
    "seed": "lecture helmet measure outdoor payment select subway bracket sniff update decorate worth assume ball auto spray glass shiver suffer avoid regret glass foot stay",
    "url": "https://zecvote.zone/election/1d075a9b9e0b53072efebff331722d99a74bc7f21b6d26f0600d47d377a67e2b"
  },
  {
    "question": 7,
    "topic": "Project Tachyon",
    "seed": "key program glue ankle hold jewel issue payment forget protect relief flower cannon clock flat clever enough identify once rotate two boss they horror",
    "url": "https://zecvote.zone/election/340534dc1a42a2faef9fe57ecff609526d8433e5e9a9f6feac6d09fe1f0d5d2d"
  },
  {
    "question": 8,
    "topic": "STARK Proof Verification (via TZEs)",
    "seed": "oppose boy tumble gesture volume zoo cushion burden banana rose leisure input lock narrow sleep custom equip try become catch slim ahead scale chief",
    "url": "https://zecvote.zone/election/89a963d3ea444af7af7460b5c9f6c1aff5b4dc6cbd9b4356f9ef24591fcef626"
  },
  {
    "question": 9,
    "topic": "Dynamic Fee Mechanism",
    "seed": "neutral toe battle staff claim error burden poem theme depend hawk decline wish name stereo chalk height slide anchor picture alley fury prosper post",
    "url": "https://zecvote.zone/election/a816627d9b7c36116c150d2e80cbda64c616556733cbdeeaf6572db849405335"
  },
  {
    "question": 10,
    "topic": "Consensus Accounts",
    "seed": "aunt connect globe furnace solid direct region ozone canoe team mutual task patient immense live shallow detail nephew miracle cream broken thank oxygen large",
    "url": "https://zecvote.zone/election/b94cacd2a847e2996048b9371a4b4eb989decd8cfa0d3ebb06d0bb6527eb7c3f"
  },
  {
    "question": 11,
    "topic": "Orchard Quantum Recoverability",
    "seed": "rookie era stereo hire success south butter brown chef destroy tortoise pilot stable robust relax spatial short verb force material pair dress coconut hidden",
    "url": "https://zecvote.zone/election/7fa15c2d77bb5b1ad3bec984d95bd5a61954494d6cba2cc2c71a3d85aec0963e"
  }
]"#;
