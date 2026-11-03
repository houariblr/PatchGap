function setOwner(address next) external {
    require(msg.sender == owner);
    require(next != address(0));
    owner = next;
}
