# Workflow Templates
This holds various Github Actions workflows that abstract pipeline functionality

## Usage
In your .github/workflows/*.yml, include the desired workflow template. i.e:
```
jobs:
  build:
    uses: khumozin/workflow-templates/.github/workflows/angular-build-app.yml@<release-version>
    with:
      node_version: "['22.x']"
```
