contract C { uint256 totalSupply; mapping(address => uint256) balance;
    function mint(uint256 amount) external { balance[msg.sender] += amount; totalSupply += amount; } }
