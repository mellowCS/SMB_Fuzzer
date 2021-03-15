pub mod smb2;

fn main() {
    println!("{}", smb2::header::SyncHeader::default());
}
