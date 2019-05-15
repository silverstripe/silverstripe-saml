# Contribution guidelines
This document describes additional contribution guidelines that apply to this module only.

## Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Documentation](#documentation)
- [Adding new functionality](#adding-new-functionality)
- [Adding support for new identity providers (IdPs)](#adding-support-for-new-identity-providers-idps)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Documentation
All changes should be documented to a similar (or better) level as the existing code.

If you add or change headings in any of the existing documentation files, or create a new markdown file, make sure you re-run `./build-toc`:

- `npm install -g doctoc`
- `cd /path/to/module/docs/en`
- `./build-toc`

If the above doesn't work because build-toc fails or similar, feel free to submit your PR without updating the table of contents and we can do this upon merge.

## Adding new functionality
This module follows semantic versioning, therefore id you change anything that breaks backwards compatibility that will require a new major release. Please be clear about this when creating new pull requests. Alternatively, you can get you feature merged faster if you include YML configuration to disable your feature, and make it optional to enable.

If you add additional functionality, make sure to document it both in the codebase as well as the appropriate file in the docs directory.

## Adding support for new identity providers (IdPs)
Adding support for new IdPs generally means you also need to add documentation that describes how that IdP should be configured to work with this module.

For an example of the level of detail to include, see the existing documentation for [Azure AD](azure-ad.md) and [ADFS](adfs.md). Generally, this should describe at a high level exactly what you expect from the administrator of the IdP, and should be a document that you are comfortable sending to your IdP sysadmin to implement. 
