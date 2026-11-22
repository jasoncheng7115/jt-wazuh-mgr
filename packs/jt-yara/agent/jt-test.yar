rule JT_Wazuh_YARA_Test {
  meta:
    description = "Harmless marker used to test the Wazuh YARA active response"
  strings:
    $m = "JT-WAZUH-YARA-TEST-7f3a9c"
  condition:
    $m
}
