use testaa;

fn main() {
    match testaa::op_run(){
        Err(e) => {
            println!("{:?}", e.to_string());
        }
        Ok(()) =>{}
    };
}



