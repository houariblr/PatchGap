function setOwner(address next) external {
    require(msg.sender == owner);
    owner = next;
}
