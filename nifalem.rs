use std::io;
use std::fs::File;
use std::io::{BufRead, BufReader};

use capstone::prelude::*;
use capstone::{CsInsn, CsMode, CsArch, CsSyntax};

fn main() {
    let filename1 = prompt("Enter the first file name: ");
    let filename2 = prompt("Enter the second file name: ");

    let instruction_list1 = disassemble(&filename1);
    let instruction_list2 = disassemble(&filename2);

    compare_instructions(&instruction_list1, &instruction_list2);
}

fn prompt(message: &str) -> String {
    println!("{}", message);
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Error reading input");
    input.trim().to_string()
}

fn disassemble(filename: &str) -> Vec<CsInsn> {
    let mut cs = Capstone::new()
        .mode(CsMode::Mode32)
        .arch(CsArch::ARCH_X86)
        .syntax(CsSyntax::SYNTAX_INTEL)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let f = File::open(filename).expect("Error opening file");
    let reader = BufReader::new(f);
    let mut disassembly_list = Vec::new();

    let bytes: Vec<u8> = reader.lines()
        .map(|line| hex::decode(line.expect("Error parsing line")).expect("Error decoding hex"))
        .flatten()
        .collect();

    let r = cs.disasm_all(&bytes, 0x0).unwrap();

    for i in r.iter() {
        disassembly_list.push(i);
    }

    disassembly_list
}

fn compare_instructions(instruction_list1: &Vec<CsInsn>, instruction_list2: &Vec<CsInsn>) {
    let len = std::cmp::min(instruction_list1.len(), instruction_list2.len());
    for i in 0..len {
        let instruction1 = &instruction_list1[i];
        let instruction2 = &instruction_list2[i];

        if instruction1.bytes() != instruction2.bytes() {
            println!("Instructions differ at address: 0x{:x}", instruction1.address());
            println!("{}\t{}", instruction1.mnemonic().unwrap_or(""), instruction1.op_str().unwrap_or(""));
            println!("{}\t{}", instruction2.mnemonic().unwrap_or(""), instruction2.op_str().unwrap_or(""));
        }
    }
}
