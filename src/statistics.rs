use crate::types::Attempt;
use serde::Serialize;
use std::collections::BTreeMap;
#[derive(Debug, Serialize)]
pub struct Summary {
    pub attempts: usize,
    pub successes: usize,
    pub success_percent: f64,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub average_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub failures: BTreeMap<String, usize>,
}
pub fn summarize(rows: &[&Attempt]) -> Summary {
    let mut times: Vec<f64> = rows
        .iter()
        .filter(|a| a.success)
        .map(|a| a.total_ms)
        .collect();
    times.sort_by(f64::total_cmp);
    let n = times.len();
    let mut failures = BTreeMap::new();
    for a in rows {
        if let Some(e) = &a.error {
            *failures.entry(e.code.clone()).or_insert(0) += 1;
        }
    }
    Summary {
        attempts: rows.len(),
        successes: n,
        success_percent: if rows.is_empty() {
            0.
        } else {
            100. * n as f64 / rows.len() as f64
        },
        min_ms: times.first().copied(),
        max_ms: times.last().copied(),
        average_ms: if n == 0 {
            None
        } else {
            Some(times.iter().sum::<f64>() / n as f64)
        },
        p95_ms: if n == 0 {
            None
        } else {
            Some(times[(95 * n).div_ceil(100) - 1])
        },
        failures,
    }
}
pub fn grouped(rows: &[Attempt]) -> BTreeMap<String, Summary> {
    let mut groups: BTreeMap<String, Vec<&Attempt>> = BTreeMap::new();
    for a in rows {
        groups
            .entry(format!("host:{}", a.hostname))
            .or_default()
            .push(a);
        if let Some(ip) = a.ip {
            groups
                .entry(format!("ip:{}/{ip}", a.hostname))
                .or_default()
                .push(a);
        }
    }
    groups
        .into_iter()
        .map(|(k, v)| (k, summarize(&v)))
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nearest_rank_and_failures() {
        let mut rows: Vec<_> = (1..=20)
            .map(|n| {
                let mut a = Attempt::new("host".into(), None, 443, 1);
                a.success = true;
                a.total_ms = n as f64;
                a
            })
            .collect();
        rows.push(Attempt::new("host".into(), None, 443, 1));
        let s = summarize(&rows.iter().collect::<Vec<_>>());
        assert_eq!(s.p95_ms, Some(19.));
        assert_eq!(s.average_ms, Some(10.5));
        assert_eq!(s.successes, 20);
        assert_eq!(summarize(&[]).p95_ms, None);
    }
}
