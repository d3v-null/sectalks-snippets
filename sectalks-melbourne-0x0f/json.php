<?php

require 'classes/db.php';
require 'classes/phpfix.php';
require 'classes/user.php';

$data = array('key'=>'username:derwent,username:admin,blah:', 'value'=>'derwent');

echo "data:";
print_r($data);
echo "sign:";
$sign = jwt::sign($data);
print_r($sign);

?>
