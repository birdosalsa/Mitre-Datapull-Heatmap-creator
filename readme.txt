MITRE ATT&CK Data Analysis and Visualization Tool

Description:
This Python script is a comprehensive tool for fetching, analyzing, and visualizing data from the MITRE ATT&CK framework. It primarily focuses on gathering information about tactics, techniques, and procedures (TTPs) used by various threat groups. The script offers features like data extraction from MITRE's web pages, data transformation, and presentation in various formats including CSV exports, heat maps, and interactive network graphs.

Key Features:
Data Extraction: Gathers the latest tactics and techniques from MITRE ATT&CK framework for enterprise, ICS, and mobile environments.
Data Transformation: Cleans and structures the data for analysis.
Visualization: Creates heat maps and network trees to visualize the relationships and probabilities of different techniques.
Export Options: Allows exporting data in CSV format for external use.
Interactive Analysis: Provides an interactive approach to exploring the TTPs of specific threat groups.

Installation
Before running the script, ensure the following Python libraries are installed:

pandas
numpy
scipy
networkx
matplotlib
seaborn
bs4 (BeautifulSoup)
asyncio
httpx
You can install these packages using pip:

bash
Copy code:
pip install pandas numpy scipy networkx matplotlib seaborn beautifulsoup4 asyncio httpx
Usage
Run the script using Python:

bash
Copy code:
python mitre_scrapping_data_retrieval.py

Interactive Options
The script prompts for user input to choose specific functionalities, such as:

Exporting Data: Choose the type of data to export as CSV.
Generating Heat Map: Visualize the frequency of TTPs used by a threat group.
Creating Probability Network Map: Explore an interactive network graph representing the likelihood of different techniques.
Outputs
CSV Files: Exported to the Downloads folder with information about associated names, techniques, software, and campaigns.
Heat Map Image: A visual representation of TTPs, saved as an image file.
Network Graph: An interactive graph showing the probability and connections between different techniques.
Notes
The script makes HTTP requests to attack.mitre.org to fetch the latest data.
Visualization features like heat maps and network graphs require graphical support on the running environment.