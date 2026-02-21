use std::collections::BTreeSet;

use anyhow::Error;
use bip0039::Mnemonic;
use orchard::{keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey}, vote::{try_decrypt_ballot, validate_ballot, Ballot, BallotData, OrchardHash}};
use pasta_curves::{group::ff::PrimeField, Fp};
use serde::{Deserialize, Serialize};
use zcash_vote::{
    address::VoteAddress,
    as_byte256,
    election::{Election, BALLOT_VK},
};

#[derive(Clone, Debug)]
pub struct Count(PreparedIncomingViewingKey, FullViewingKey, u64);

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CountResult {
    choice: String,
    amount: u64,
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

    // Right-align integer, left-align fractional (dot + up to 5 digits)
    format!("{:>10}{:<6}", separated, frac_part)
}

fn fmt2(val: u64) -> String {
    let whole = val / 100_000_000;
    let frac = val % 100_000_000;

    // Whole part: group 3s from the right
    let s = whole.to_string();
    let whole_str: String = s
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("_");

    // Fractional part: 8 digits, group 3s from the left
    let f = format!("{:08}", frac);
    let frac_str: String = f
        .as_bytes()
        .chunks(3)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("_");

    format!("{}.{}", whole_str, frac_str)
}

#[tauri::command]
async fn audit(url: String, seed: String) -> Result<Vec<CountResult>, String> {
    let res = async {
        let election: Election = reqwest::get(&url).await?.json().await?;
        let mnemonic = Mnemonic::from_phrase(&seed)?;
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
        let n = reqwest::get(&format!("{url}/num_ballots"))
            .await?
            .text()
            .await?;
        let n = n.parse::<u32>()?;
        for i in 1..=n {
            let raw: serde_json::Value = reqwest::get(&format!("{url}/ballot/height/{i}"))
                 .await?
                 .json()
                 .await?;

            // if i == 1 {
            //     println!("Ballot 1 raw JSON:\n{}", serde_json::to_string_pretty(&raw)?);
            // }

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
                        println!("Ballot {:>3}: {} ZEC -> {:>7}, ({:>21})", i, fmt(note.value().inner()), election.candidates[idx].choice, fmt2(note.value().inner()));
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

        let res = counts
            .iter()
            .zip(election.candidates.iter())
            .map(|(c, cc)| CountResult {
                choice: cc.choice.clone(),
                amount: c.2,
            })
            .collect::<Vec<_>>();
        Ok::<_, Error>(res)
    };

    res.await.map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![audit])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
