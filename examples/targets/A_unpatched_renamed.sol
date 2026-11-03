contract A { address admin;
    // same logic, different names
    function changeAdmin(address who) external { require(msg.sender == admin); admin = who; } }
