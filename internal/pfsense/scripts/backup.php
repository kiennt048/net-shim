<?php
error_reporting(0);

$config_file = '/cf/conf/config.xml';

if (!file_exists($config_file)) {
    die("ERROR:CONFIG_NOT_FOUND");
}

$content = file_get_contents($config_file);
if ($content === false) {
    die("ERROR:READ_FAILED");
}

// Return the config content
echo $content;
?>