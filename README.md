# scoperunner
A tool developed to help automating some initial steps of vulnerability assessment on web hosts, integrating several tools to build a smooth experience when hunting bugs.

In order to work with scoperunner you must have installed:
*  python
*  paramspider
*  nuclei (optional)

proceed with your analysis by providing adequate setup, that is, clone this repo and add a file called `scope`, containing a list of urls in the format `https://example.com`. Run the tool by either providing -nuclei or resume flags, to run nuclei on a refined scope and resume from early stages.
