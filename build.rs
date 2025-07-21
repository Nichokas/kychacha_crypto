fn main() {
    let mut mlkem_features: u32 = 0;
    let mut bincode_features: u32 = 0;

    #[cfg(feature = "mlkem512")]
    {mlkem_features += 1;};
    #[cfg(feature = "mlkem768")]
    {mlkem_features += 1;}
    #[cfg(feature = "mlkem1024")]
    {mlkem_features += 1;}

    if mlkem_features != 1 {
        panic!("You cannot use none or two versions of ML-KEM at the same time. Correct the feature flags.");
    }
}