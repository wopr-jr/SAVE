from dataclasses import dataclass
from enum import enum
from typing import List
from Pydantic import uuid


## RULES

class Severity(Enum):
    unknown = 0
    low = 1
    medium = 2
    three = 3

class Status(Enum):
    not_reviewed = 0
    not_applicable = 1
    open = 2
    not_a_finding = 3

@dataclass
class STIG_CHECK_REFERENCE:
    # Each level in the group heirarchy is stored, with the earlier entries in the array representing higher levels of the tree
    name: str
    href: str

@dataclass
class STIG_GROUP:
    id: str
    title: str
    description: str

@dataclass
class STIG_OVERRIDE:
    additional_properties = bool
    pattern_properties = 

@dataclass
class RULE_PROPERTIES:
    # A unique identifier for the checklist rule
    uuid: str
    # The UUID of the origin STIG
    stig_uuid: str
    # A prettier version of group_id_src for display, removes text like 'xccdf_mil.disa.stig_group_'
    group_id: str
    # The GroupID from the rule in the origin STIG
    group_id_src: str
    # A prettier version of rule_id_src for rule display, removes text like 'xccdf_mil.disa.stig_rule_' or 'rule_'
    rule_id: str
    # The RuleID from the rule in the origin STIG
    rule_id_src: str
    # The identifier value from the Reference tag
    target_key: str | None = None
    stig_ref: str | None = None
    # Weight from origin STIG
    weight: str
    # Class from origin STIG
    classification: str
    # Severity from origin STIG
    severity: Severity
    # Rule_Ver from origin STIG
    rule_version: str
    # Rule_Title from origin STIG
    rule_title: str
    # FixText from origin STIG
    fix_text: str
    # The identifier value from the Reference tag
    reference_identifier: str | None = None
    # Group_Title from origin STIG
    group_title: str
    # False_Positives from origin STIG
    false_positives: str
    # False_Negatives from origin STIG
    false_negatives: str
    # Discussion from origin STIG
    discussion: str
    # CheckContent from origin
    checkcontent: str
    # Documentable from origin STIG
    documentable:str
    # Mitigations from origin STIG
    mitigations: str
    # Potential_Impacts from origin STIG
    potential_impacts: str
    # Third_Party_Tools from origin STIG
    third_party_tools: str
    # Mitigation_Control from origin STIG
    mitigation_control: str
    # Responsibility from origin STIG
    responsibility: str
    # Security_Override_Guidance from origin STIG
    security_override_guidance: str
    # IA_Controls from origin STIG
    ia_controls: str
    # Check_Content from origin STIG
    check_content: str | None = None
    # CheckContentRef from origin STIG
    check_content_ref: STIG_CHECK_REFERENCE | None = None
    # LEGACY_ID array from origin STIG
    legacy_ids: List[str]
    # CCI_REF array from origin STIG
    ccis: List[str]
    # An list showing the hierarchy of the group tree structure
    group_tree: List[STIG_GROUP]
    # The datetime string for the time the rule was added
    created_at: str
    # The datetime string for the last time the rule was modified
    updated_at: str
    # The STATUS field of the rule
    status: Status
    #  Allows rule properties to be overridden without data-loss of the original value. Currently, only 'severity' is used
    overrides: STIG_OVERRIDE
    # Comments about the current rule
    comments: str
    # Finding details for the current rule, usually information about the tool that was used to generate the finding
    finding_details: str
    # [Deprecated] Not Used
    STIGUuid: str

@dataclass
class STIG_RULE:
    description: str
    additional_properties: bool
    properties: RULE_PROPERTIES

## STIGS

@dataclass
class STIG_PROPERTIES:
    # The Full STIG name taken from the title feild of the original STIG
    stig_name: str
    # Pretty name
    display_name: str
    # The benchmark ID taken from the original STIG
    stig_id: str
    # The release info taken from the origin STIG, usually contains the STIG version and release date
    release_info: str
    # Identifier used for a specific STIG
    uuid: uuid.UUID
    # The reference id from the first rule in the checklist
    reference_identifier: str | None = None
    # The TOTAL number of rules in the origin STIG, even if rules were cherrypicked.
    size: int
    # The list of STIGs
    rules: STIG_RULE
    
@dataclass
class STIG:
    description: str
    type: object
    additional_properties: bool
    required: List[str] = ["stig_name","display_name","stig_id","release_info","uuid","size"]
    properties: STIG_PROPERTIES

## Assets

@dataclass
class ASSET_PROPERTIES:
    target_type: str = "Computing"
    host_name: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    fqdn: str | None = None
    comments: str | None = None
    role: str | None = None
    technology_area: str | None = None
    target_key: str | None = None
    is_web_database: bool = False
    web_db_site: str | None = None
    web_db_instance: str | None = None
    classification: str | None = None

@dataclass
class TARGET_ASSET:
    description: str
    type: object
    additional_properties: bool
    required: List[str] | None = None
    properties: ASSET_PROPERTIES

## Checklists

@dataclass
class CHECKLIST_PROPERTIES:
    # The STIG filename when it was last saved
    title: str
    # [Optional] Checklist type (cklb, ckl, csv, etc) 
    checklist_type: str
    # [Optional] Checklist version
    checklist_version: str = "1.0"
    # [Optional] Properties of the scanned system
    target_data: TARGET_ASSET
    # [Optional] A list of STIGs contained in the checklist
    stigs: List[STIG]

@dataclass
class CKL_PROPERTIES(CHECKLIST_PROPERTIES):
    # [Optional] Checklist type (cklb, ckl, csv, etc) 
    checklist_type: str = 'ckl'

@dataclass
class CKL_CHECKLIST:
    properties: CKL_PROPERTIES

@dataclass
class CKLB_PROPERTIES(CHECKLIST_PROPERTIES):
    # [Optional] Checklist type (cklb, ckl, csv, etc) 
    checklist_type: str = 'cklb'
    # UUID of the checklist
    id: uuid.UUID
    # [Optional] for internal use by SV3
    active: bool
    # [Optional] Used by SV3 to track if the checklist is in build or fill mode
    mode: int
    # [Optional] for internal use by SV3
    has_path: bool

@dataclass
class CKLB_CHECKLIST:
    schema: str
    title: str
    description: str
    additional_properties: bool
    required: List[str] = ["title", "id"]
    properties: CKLB_PROPERTIES


