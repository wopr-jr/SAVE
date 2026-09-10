# parse_stig_rules()
"stig_rule": {
	  
      
        "group_tree": {
          "description": "An array showing the hierarchy of the group tree structure",
          "type": "array",
          "items": {
			"description":"Each level in the group heirarchy is stored, with the earlier entries in the array representing higher levels of the tree",
            "type": "object",
            "properties": {
              "id": {
                "type": "string"
              },
              "title": {
                "type": "string"
              },
              "description": {
                "type": "string"
              }
            }
          }
        },
        "createdAt": {
          "description": "The datetime string for the time the rule was added to the SV3 library",
          "type": "string"
        },
        "updatedAt": {
          "description": "The datetime string for the last time the rule was modified in the SV3 Library",
          "type": "string"
        },
        "status": {
          "description": "The STATUS field of the rule",
          "type": "string",
          "enum": [
            "not_reviewed",
            "not_applicable",
            "open",
            "not_a_finding"
          ]
        },
        "overrides": {
          "Description": "Allows rule properties to be overridden without data-loss of the original value. Currently, only 'severity' is used",
          "additionalProperties": false,
          "patternProperties": {
            "^[a-zA-Z_]+$": {
              "type": "object",
              "additionalProperties": false,
              "properties": {
                "reason": {
                  "description":"Justification for overriding the property",
                  "type": "string"
                }
              },
              "patternProperties": {
                "^[a-zA-Z_]+$": {
                  "type": "string"
                }
              }
            }
          }
        },
        "comments": {
          "description": "Comments about the current rule",
          "type": "string"
        },
        "finding_details": {
          "description": "Finding details for the current rule, usually information about the tool that was used to generate the finding",
          "type": "string"
        },
        "STIGUuid": {
          "description": "[Deprecated] Not Used",
          "type": "string"
        }
      }
    }
# parse_stig_data()

# parse_target_data()

# parse_checklist_data()
  
## examine_file(file)
# Determine if supported type
# if supported -> correct_parser(file)

## examine_input(input)
# Determine if file or directory
# if directory -> for file in directory : examine_file(input)
# if file -> examine_file(input)

## MAIN
#Accept input -> input
#   examine_input(input)



## main