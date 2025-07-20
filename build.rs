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

    #[cfg(feature = "bincode_normal_limit")]
    {bincode_features += 1;};
    #[cfg(feature = "bincode_big_limit")]
    {bincode_features += 1;};
    #[cfg(feature = "bincode_no_limit")]
    {
        bincode_features += 1;
        print!("cargo::warning=You have selected a feature flag that removes the memory limit for the data serialization, THIS PROGRAM IS SUSCEPTIBLE TO OOM ATTACKS IF YOU DONT CHANGE THIS FLAG");
    };
    if bincode_features != 1 {
        panic!("You cannot use none or two different configurations of bincode serialization at the same time. Correct the feature flags.");
    }
}