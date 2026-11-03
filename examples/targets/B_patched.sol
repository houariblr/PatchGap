contract B { address admin;
    function changeAdmin(address who) external { require(msg.sender == admin); require(who != address(0)); admin = who; } }
