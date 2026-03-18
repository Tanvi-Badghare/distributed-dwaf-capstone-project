// Iterate over first 3 features using iterator (Clippy-compliant)
for (tree, feature) in feature_vars.iter().enumerate().take(3) {
    let val = feature.clone();

    // Example scoring logic (keep your existing logic here)
    score += val * weights[tree];

    // If you had thresholds or branching, keep using `tree`
    // e.g.
    // if val > thresholds[tree] { ... }
}