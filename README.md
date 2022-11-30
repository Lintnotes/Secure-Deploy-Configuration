# Secure Deploy Configuration

**Secure Deploy Configuration** or **SDC** is a PowerShell driven solution that can be leveraged to deploy secure DoD STIG Compliant images.  SDC will apply all Operating System STIGS and any associated configuration settings such as removing items like features, Modern Applications and configuring OS Branding.


## Purpose

This solution was created in order to quickly deploy a secure image with corporate branding while elminating the complexity of other toolsets to accelerate deployments with a proven scalable solution.

## Getting Started

1. Download the SDC.zip and Apply-SDC.ps1 file and modify any of the parameters in the Apply-SDC.ps1 file to meet your organization requirements.
2. If deploying from Azure or another cloud provider supply the URI of where you have the SDC.zip file located.
3. Replace any of the OS Branding files in the sdc.zip with your corporate wallpapers, lockscreen and logos.
4. Deploy the Apply-SDC.ps1 script via Custom Script Extenion, Run Command or other mechanisms at VM Creation time.

## Contributing
We welcome all contributions to the development of SDC. There are several different ways you can help. Deploy the solution and report feedback and issues, Provide code merge requests or help with documentation.

Thank you to everyone that has reviewed the project and provided feedback through issues. We are especially thankful for those who have contributed pull requests to the code and documentation.

### Contributors

@Lintnotes (Brandon Linton)
