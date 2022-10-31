from GetRemediationGuidance import *


# Test no match on AttackSurfaceRuleID
def test_command(mocker):
    args = {'AttackSurfaceRuleID': 'test'}
    entry = get_remediation_guidance_command(args)
    assert entry.outputs == "Get in touch with your Infosec team to define proper remediation access."
    assert entry.outputs_prefix == 'RemediationGuidance'


# Test match on AttackSurfaceRuleID
def test_known(mocker):
    args = {'AttackSurfaceRuleID': 'AtlassianCrucible'}
    entry = get_remediation_guidance_command(args)
    p1 = "Remediation guidance: Determine whether this asset should be exposed to the public internet or not."
    p2 = "\nAfterwards, work with the asset owner to remove the asset should it be determined that the asset should "
    p3 = "not be publicly accessible."
    p4 = "\n\nGet in touch with your Infosec team to define proper remediation access."
    expected = p1 + p2 + p3 + p4
    assert entry.outputs == expected
    assert entry.outputs_prefix == 'RemediationGuidance'
