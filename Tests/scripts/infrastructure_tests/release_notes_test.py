
single_rn_input1 = 'single releasenote'
single_rn_input2 = 'Single releasenote'
single_rn_input3 = 'single releasenote.'
single_rn_input4 = 'Single releasenote.'
single_rn_output = 'Single releasenote.'

multi_rn_input1_1 = '''  - RN 1.
  - RN 2.'''
multi_rn_input1_2 = '''RN 1.
  - RN 2.'''
multi_rn_input1_3 = '''  - RN 1.
  - RN 2'''
multi_rn_input1_4 = '''  - RN 1.
  -RN 2.'''
multi_rn_input1_5 = '''  - RN 1
  - RN 2.'''
multi_rn_input1_6 = '''
  - RN 1
  - RN 2.
'''
multi_rn_input1_7 = '''
  - RN 1
  - RN 2.
   '''

multi_rn_output1 = '''  - RN 1.
  - RN 2.'''

multi_rn_input2_1 = '''  - RN 1.
  - Added 4 new commands.
    - ***hello***
    - ***world***
    - ***hello-world***
  - RN 2.'''
multi_rn_input2_2 = '''  - RN 1.
  - Added 4 new commands
    - ***hello***
    - ***world***
    - ***hello-world***
  - RN 2.'''
multi_rn_input2_3 = '''- RN 1.
- Added 4 new commands.
    - ***hello***
    - ***world***
    - ***hello-world***
- RN 2.'''
multi_rn_input2_4 = '''  - RN 1.
  - Added 4 new commands.
    - ***hello***
    - ***world***
    ***hello-world***
  - RN 2.'''
multi_rn_input2_5 = '''  - RN 1.
  - Added 4 new commands.
    - ***hello***
    - ***world***
    - ***hello-world***
  - RN 2.'''
multi_rn_input2_6 = '''  - RN 1.
Added 4 new commands.
    - ***hello***
    - ***world***
    - ***hello-world***
  - RN 2.'''

multi_rn_input2_7 = '''  - RN 1.
  - Added 4 new commands.
    - ***hello***
    - ***world***
    - ***hello-world***
      - RN 2.'''

multi_rn_output2 = '''  - RN 1.
  - Added 4 new commands.
    - ***hello***
    - ***world***
    - ***hello-world***
  - RN 2.'''


def test_add_dot():
    from release_notes import add_dot

    assert add_dot(single_rn_input1) == single_rn_output
    assert add_dot(single_rn_input2) == single_rn_output
    assert add_dot(single_rn_input3) == single_rn_output
    assert add_dot(single_rn_input4) == single_rn_output

    assert add_dot(multi_rn_input1_1) == multi_rn_output1
    assert add_dot(multi_rn_input1_2) == multi_rn_output1
    assert add_dot(multi_rn_input1_3) == multi_rn_output1
    assert add_dot(multi_rn_input1_4) == multi_rn_output1
    assert add_dot(multi_rn_input1_5) == multi_rn_output1
    assert add_dot(multi_rn_input1_6) == multi_rn_output1
    assert add_dot(multi_rn_input1_7) == multi_rn_output1

    assert add_dot(multi_rn_input2_1) == multi_rn_output2
    assert add_dot(multi_rn_input2_2) == multi_rn_output2
    assert add_dot(multi_rn_input2_3) == multi_rn_output2
    assert add_dot(multi_rn_input2_4) == multi_rn_output2
    assert add_dot(multi_rn_input2_5) == multi_rn_output2
    assert add_dot(multi_rn_input2_6) == multi_rn_output2
