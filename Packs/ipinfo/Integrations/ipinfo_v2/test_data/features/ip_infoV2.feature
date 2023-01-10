Feature: This is a demo of Behave with IPInfo

  Scenario: Valid IP Address
    Given an ip-address which is valid
     When running the ip command
     Then the result should contain valid info

  Scenario: Invalid IP Address
    Given an ip-address which is not valid
     When running the ip command
     Then the command should return an error