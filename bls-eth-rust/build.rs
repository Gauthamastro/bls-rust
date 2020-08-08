fn main(){
    println!("cargo:rustc-link-search=bls-eth-rust/lib/linux/amd64");
    println!("cargo:rustc-link-lib=bls384_256");
}