//SPDX-License-Identifier: MIT
pragma solidity ^0.8;

contract MessageManager {

    struct Message {
        uint256 tx;
        address sender;
        address receiver;
    }

    uint public index;
    mapping(address => Message[]) public sent_by;
    mapping(address => Message[]) public received_by;

    mapping(address => bytes) public publicKeys;

    event NewTx(uint indexed tx_id, address indexed sender, address indexed receiver);

    constructor(){
        index = 0;
    }

    function sent_by_counter(address sender) external public {
        return sent_by[sender].length;
    }

    function received_by_counter(address receiver) external public {
        return received_by[receiver].length;
    }

    function send_message(address receiver, bytes calldata publicKey) public {
        if (publicKeys[msg.sender].length == 0) {
            publicKeys[msg.sender] = publicKey;
        }
        index++;
        emit NewTx(index, msg.sender, receiver);
        sent_by[msg.sender].push(Message(index,msg.sender,receiver));
        received_by[receiver].push(Message(index,msg.sender,receiver));
        sent_by_counter[msg.sender]++;
        received_by_counter[receiver]++;
    }

}