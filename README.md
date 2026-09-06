# SAVE
  The goal of this project is to produce a Security And Vulnerability Evaluation (SAVE) server that can take checklists of any form and use their data to produce reports, POAMS, and remediation plans along with multi-domain (program) tracking abilities.

# General thoughts on architecture 

  ## Function encapsulation
  This project will begin with each general function (file parsing, report generation, etc) desired in the finalized sever encapsulated as a standalone program. This is both for testing purposes as well as for users to be able to pick and choose functions that work in their environment to build their own custom solutions.
  
  ## Why a server?
  I have noticed that across different environments, companies, agencies, and security domains that resources available to the administrators is extremely variable. Direct application execution might be difficult to achieve, python might not be installed or available, or the paperwork required for a program to be installed on every admin's machine might be onerous to the point of inviability. Therefore I have decided that the best design choice to be as useful to as many places as possible is to make a secure, lightweight, and centralized solution that requires the least effort to set up. I fully intend to continue maintaining the stand-alone programs mentioned above in cases where adding to an environment just is not possible, but will not be optimizing them for any other environment other than my own (Linux/x86_64).

# Project Roadmap (tentative)
  ## Define parsers for the various checklist formats
  This includes making a standardized format so all checklist data can be normalized.
  
  ## Define storage backend
  Probs gunna use SQLite for now NGL
  
  ## Define checklist creators (reverse parser?)
  The data ingested should be able to be exported to any other ingest-able format
  
  ## Define parsers for Evaluate-Stig answer files. 
  Answer files that do not require extra tests can be uploaded to update existing scans so additional E-Stig runs are not required. 
  
  ## Define report and POAM generators 
  Create the ability for users to define desired reports based off of imported checklists.

  ## Define remediation planner

  ## Transfer to server architecture... I'll deal with this later
