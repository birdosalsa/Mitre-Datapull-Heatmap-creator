import pandas as pd
import numpy as np
import scipy.stats as stats
import networkx as nx
import matplotlib.pyplot as plt
import seaborn as sns
import math
import sys
import os
from bs4 import BeautifulSoup
import asyncio
import httpx
from datetime import date
from matplotlib.gridspec import GridSpec
import textwrap

print("Starting up! Getting most recent Tactics and Techniques from Mitre!")
def get_tactics(urls):
    tactics = []
    source = ['enterprise', 'ics', 'mobile']
    for url in urls:
        # Determine the source based on the URL
        if '/enterprise/' in url:
            current_source = 'Enterprise'
        elif '/ics/' in url:
            current_source = 'ICS'
        elif '/mobile/' in url:
            current_source = 'Mobile'
        else:
            current_source = 'Unknown'
            
        resp_tac = httpx.get(url)
        html = resp_tac.text
        soup = BeautifulSoup(html, 'html.parser')
        table = soup.find('table')
        rows = table.find_all('tr')
        headers = [header.text.strip() for header in rows[0].find_all('th')]
        
        for row in rows[1:]:
            cols = row.find_all('td')
            row_data = [cell.text.strip() for cell in cols]
            row_data.append(current_source)  # Add source to each row
            tactics.append(row_data)
            
    headers.append('Source')    
    tactics_df = pd.DataFrame(tactics, columns = headers)
    return tactics_df

url_tactics = ['https://attack.mitre.org/tactics/enterprise/', 'https://attack.mitre.org/tactics/ics/', 'https://attack.mitre.org/tactics/mobile/'] 
tactics_df = get_tactics(url_tactics)  

def get_techniques(tactics_df):
    techniques = []
    previous_technique_id = None  # To keep track of the main technique ID

    for index, row in tactics_df.iterrows():
        tactic_id = row['ID']
        tactic_name = row['Name']
        url = f"https://attack.mitre.org/tactics/{tactic_id}/"
        
        resp_tac = httpx.get(url)
        html = resp_tac.text
        soup = BeautifulSoup(html, 'html.parser')
        table = soup.find('table')
        
        if table:
            rows = table.find_all('tr')
            for row in rows[1:]:
                cols = row.find_all('td')
                if cols and len(cols) >= 3:
                    technique_id = cols[0].text.strip()
                    full_technique_name = cols[1].text.strip()
                    technique_description = cols[2].text.strip()

                    # Check if the name indicates a subtechnique
                    if '.' in full_technique_name:
                        subtechnique_id = full_technique_name  # Original technique name is the subtechnique ID
                        technique_name = technique_description  # Move description to name
                        technique_id = previous_technique_id  # Set the main technique ID for the subtechnique
                    else:
                        subtechnique_id = ''
                        technique_name = full_technique_name
                        previous_technique_id = technique_id  # Update the main technique ID

                    techniques.append([tactic_id, tactic_name, technique_id, technique_name, technique_description, subtechnique_id])
        else:
            print(f"No table found in URL: {url}")

    # Create a DataFrame
    techniques_df = pd.DataFrame(techniques, columns=['Tactic_ID', 'Tactic_Name', 'Technique_ID', 'Technique_Name', 'Technique_Description', 'Subtechnique_ID'])
    return techniques_df

techniques_df = get_techniques(tactics_df)

# Filter rows with non-empty 'sub_id'
mask_sub_id = techniques_df['Subtechnique_ID'] != ''

# Apply transformations only to rows with 'sub_id'
techniques_df.loc[mask_sub_id, 'Technique_ID'] = techniques_df.loc[mask_sub_id, 'Technique_ID'].fillna(method='ffill')
techniques_df.loc[mask_sub_id, 'Subtechnique_ID'] = techniques_df.loc[mask_sub_id, 'Subtechnique_ID'].fillna('').astype(str).str[:]
techniques_df.loc[mask_sub_id, 'Technique_ID'] = techniques_df.loc[mask_sub_id, 'Technique_ID'] + '' + techniques_df.loc[mask_sub_id, 'Subtechnique_ID']
techniques_df.drop('Subtechnique_ID', axis = 1, inplace = True)
tactics_list = techniques_df['Tactic_Name'].unique()

def get_groups():
    url_groups = 'https://attack.mitre.org/groups/'
    resp = httpx.get(url_groups)

    groups = []
    html = resp.text
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table')
    rows = table.find_all('tr')
    headers = [header.text.strip() for header in rows[0].find_all('th')]
        
    for row in rows[1:]:
        cols = row.find_all('td')
        groups.append([cell.text.strip() for cell in cols])

    group_mapping = {}
    name_to_id = {}
    associated_group_to_id = {}
    for entry in groups:
        group_id = entry[0]
        group_name = entry[1]
        associated_groups = entry[2]

        group_mapping[group_id] = {
            'Name' : group_name,
            'Associated Groups' : associated_groups
        }

    for group_id, details in group_mapping.items():
        group_name = details['Name'].lower()  # Convert to lowercase
        associated_groups = details['Associated Groups'].lower().split('; ')  # Convert to lowercase

        name_to_id[group_name] = group_id

        for group in associated_groups:
            group = group.strip()  # Remove any leading/trailing whitespace
            if group not in associated_group_to_id:
                associated_group_to_id[group] = []
            associated_group_to_id[group].append(group_id)
            
    return name_to_id, associated_group_to_id

groups_stuff = get_groups()
print("We have successfully gathered the data and need to know what group we should gather some data on for you!")

found_ids = []

while not found_ids:
    input_value = input("Enter a name or associated group: ").lower().strip()
    name_to_id = groups_stuff[0]
    associated_group_to_id = groups_stuff[1]
    
    # Search by name
    if input_value in name_to_id:
        found_ids.append(name_to_id[input_value])
    
    # Search by associated group
    else:
        for group, ids in associated_group_to_id.items():
            if input_value in group:
                found_ids.extend(ids)
    
    # Display the results
    if found_ids:
        apt = input_value
        print(f"Found IDs for '{input_value}': {found_ids}")
    else:
        print(f"No ID found for '{input_value}'")

gen_url = f"https://attack.mitre.org/groups/{found_ids[0]}/"
print(gen_url)

url_group = gen_url
resp = httpx.get(url_group)
html = resp.text

# Assuming html_content is your HTML data
soup = BeautifulSoup(html, 'html.parser')

# Find all tables
tables = soup.find_all('table')

dataframes = []

for table in tables:
    rows = table.find_all('tr')
    max_columns = max(len(row.find_all(['th', 'td'])) for row in rows)

    data = []
    for row in rows:
        cols = row.find_all(['th', 'td'])
        row_data = [ele.text.strip() for ele in cols]
        row_data += [''] * (max_columns - len(cols))  # Fill missing columns with empty strings
        data.append(row_data)
    headers = data.pop(0)
    df = pd.DataFrame(data, columns=headers)
    dataframes.append(df)

frame_names = ["Associated Names", "Techniques", "Software"]
frame_names_campaign = ["Associated Names", "Campaigns","Techniques", "Software"]

# Dictionary to hold your named DataFrames
named_dataframes = {}
if len(dataframes) < 4:
    for i, df in enumerate(dataframes):
        if i < len(frame_names):  # Check to avoid index out of range
            name = frame_names[i]
            named_dataframes[name] = df
        else:
            break  # Break the loop if there are more DataFrames than names
else:
    for i, df in enumerate(dataframes):
        if i < len(frame_names_campaign):  # Check to avoid index out of range
            name = frame_names_campaign[i]
            named_dataframes[name] = df
        else:
            break  # Break the loop if there are more DataFrames than names

def find_tactic_phase(technique_id, techniques_df, apt_techniques_df):
    matching_rows = techniques_df[techniques_df['Technique_ID'] == technique_id]
    tactic_names = set()
    rows_to_append = []
    for _, row in matching_rows.iterrows():
        if row['Tactic_Name'] not in tactic_names:
            new_row = row.copy()
            # Include the 'Use' column from apt_techniques_df
            new_row['Use'] = apt_techniques_df.loc[apt_techniques_df['ID'] == technique_id, 'Use'].iloc[0]
            rows_to_append.append(new_row)
            tactic_names.add(row['Tactic_Name'])
    return rows_to_append

# Access the DataFrame named "Associated Names"
associated_names_df = named_dataframes.get("Associated Names")

# Access the DataFrame named "Techniques"
apt_techniques_df = named_dataframes.get("Techniques")

# Access the DataFrame named "Software"
software_df = named_dataframes.get("Software")

# Access the DataFrame named "Campaign"
if len(named_dataframes) > 3:
    campaigns_df = named_dfataframes.get("Campaigns")
else:
    pass

# Check if 'Name' column contains a dot
mask = apt_techniques_df['Name'].str.contains('\.')

# If 'Name' contains a dot, copy the information to 'sub_id' column
apt_techniques_df['sub_id'] = apt_techniques_df['Name'][mask]

# Move 'Use' to 'Name' and ' ' to 'Use' if 'Name' contains a dot
apt_techniques_df.loc[mask, 'Name'] = apt_techniques_df['Use'][mask]
apt_techniques_df.loc[mask, 'Use'] = apt_techniques_df[''][mask]

# Drop the empty column ''
apt_techniques_df.drop(columns=[''], inplace=True)

# Filter rows with non-empty 'sub_id'
mask_sub_id = apt_techniques_df['sub_id'] != ''

# Apply transformations only to rows with 'sub_id'
apt_techniques_df.loc[mask_sub_id, 'ID'] = apt_techniques_df.loc[mask_sub_id, 'ID'].fillna(method='ffill')
apt_techniques_df.loc[mask_sub_id, 'sub_id'] = apt_techniques_df.loc[mask_sub_id, 'sub_id'].fillna('').astype(str).str[:]
apt_techniques_df.loc[mask_sub_id, 'ID'] = apt_techniques_df.loc[mask_sub_id, 'ID'] + '' + apt_techniques_df.loc[mask_sub_id, 'sub_id']
# apt_techniques_df.drop('sub_id', axis = 1, inplace = True)

# Iterate over the DataFrame to propagate non-blank domains
prev_domain = None
prev_id = None
for index, row in apt_techniques_df.iterrows():
    if row['Domain'] and row['Domain'] != '':  # If domain is not blank, update prev_domain and prev_id
        prev_domain = row['Domain']
        prev_id = row['ID']
    elif prev_domain:  # If domain is blank and prev_domain exists
        # Concatenate the non-blank prev_domain with the first 5 characters of the current ID and sub ID
        new_id = row['ID'].split('.')[0] + '.' + row['ID'].split('.')[1]  # Extract the main ID
        new_id = prev_id.split('.')[0] + '.' + new_id.split('.')[1] if prev_domain else row['ID']  # Concatenate with the domain if available
        apt_techniques_df.at[index, 'ID'] = new_id  # Update ID column
        apt_techniques_df.at[index, 'Domain'] = prev_domain  # Update Domain column

# Drop the 'sub_id' column
apt_techniques_df.drop('sub_id', axis=1, inplace=True)

# Apply find_tactic_phase to each row in apt_techniques_df
matching_dfs = [pd.DataFrame(find_tactic_phase(tech_id, techniques_df, apt_techniques_df)) for tech_id in apt_techniques_df['ID']]

# Concatenate the list of DataFrames into a single DataFrame
apt_tactic_phases = pd.concat(matching_dfs, ignore_index=True)

# Reset index and drop 'index' column
apt_tactic_phases.reset_index(drop=True, inplace=True)

# Drop 'Technique_Description' column
apt_tactic_phases.drop('Technique_Description', axis=1, inplace=True)

# Create a mapping dictionary from technique IDs to names
technique_id_to_name = apt_techniques_df.set_index('ID')['Name'].to_dict()

# Replace 'Technique_Name' column with technique IDs
apt_tactic_phases['Technique_Name'] = apt_tactic_phases['Technique_ID'].map(technique_id_to_name)

# Create a dictionary mapping technique IDs to their corresponding domains
id_domain_mapping = dict(zip(apt_techniques_df['ID'], apt_techniques_df['Domain']))

# Create a new 'Domain' column in apt_tactic_phases by mapping technique IDs to their corresponding domains
apt_tactic_phases['Domain'] = apt_tactic_phases['Technique_ID'].map(id_domain_mapping)

def restructure(apt_data):
    apt_data['Domain'] = apt_data['Domain'].astype('category')
    apt_data['Step'] = apt_data['Tactic_Name'].astype('category')
    
    step_order = {"Reconnaissance" : 1, "Resource Development" : 2, "Initial Access" : 3,
                  "Execution" : 4, "Persistence" : 5, "Privilege Escalation" : 6,
                  "Defense Evasion" : 7, "Credential Access" : 8, "Discovery" : 9,
                  "Lateral Movement" : 10, "Collection" : 11, "Command and Control" : 12,
                  "Exfiltration" : 13, "Impact" : 14, "Evasion" : 15,
                  "Inhibit Response Function" : 16, "Impair Process Control" : 17}
    
    apt_data = apt_data.replace({'Step':step_order})
    apt_data['Step'] = pd.to_numeric(apt_data['Step'])
    
    regex = r'\[(\d+)\]'
    
    apt_data['References'] = apt_data['Use'].astype(str).str.findall(regex).apply(','.join)
    apt_data['References'] = apt_data['References'].str.split(',')
    print(f"Below are the types of Domains that {apt} operates in:\n\n{apt_data['Domain'].value_counts()}")
    
    apt_data['Number of Occurances'] = apt_data['Use'].map(
        lambda x: ''.join(filter(lambda char: char in ['[', ']'], x)))
    apt_data['Number of Occurances'] = apt_data['Number of Occurances'].apply(
        lambda x: len(x) // 2)
    
    def is_list(element):
        return isinstance(element, list)
    apt_data['islist'] = apt_data['References'].apply(is_list)
    for data in apt_data['islist']:
        if data is False:
            print(data)
    apt_data['Step'].astype('category')
    # Ensure all elements in 'References' are lists
    apt_data['References'] = apt_data['References'].apply(lambda x: x if isinstance(x, list) else [x])
    # Reset the index of the DataFrame
    apt_data.reset_index(drop=True, inplace=True)

    # Explode the 'References'
    try:
        exploded_apt_data = apt_data.explode('References')
    except ValueError as e:
        print("Error:", e)
        
    exploded_apt_data.reset_index(inplace = True)
    exploded_apt_data.drop('islist', axis = 1, inplace = True)
    
    reference_counts = exploded_apt_data['References'].value_counts()
    
    model_data = exploded_apt_data
    model_data.drop(columns = 'index', inplace = True)
    
    return model_data, apt_data

print("We have now cleaned the group's data!")

cleaned_df = restructure(apt_tactic_phases)
model_data = cleaned_df[0]
apt_data = cleaned_df[1]

"""Heat map"""
# Function to wrap labels
def wrap_labels(labels, width=15):
    return [textwrap.fill(label, width) for label in labels]

# Prepare data for heatmap
pivot_df = apt_data.pivot_table(index=['Technique_ID', 'Technique_Name'], 
                                columns='Tactic_Name', 
                                values='Number of Occurances', 
                                aggfunc='sum', 
                                fill_value=0)

def heat_map(pivot_df):
    # List of tactics
    tactics = pivot_df.columns

    # Find global max and min for the color scale
    vmin, vmax = pivot_df.min().min() + 1, pivot_df.max().max()

    # Calculate the number of rows needed for the subplot with the most techniques
    max_rows = pivot_df.apply(lambda x: x[x > 0].shape[0], axis=0).max()

    # Adjust the figure size to make cells bigger
    # You might need to adjust these values to fit your screen or output device
    fig_width = len(tactics) * 3  # Increase the width for bigger cells
    fig_height = max_rows * 1.5  # Increase the height for bigger cells

    fig, axes = plt.subplots(1, len(tactics), figsize=(fig_width, fig_height), sharey=False)

    # Create a heatmap for each tactic
    for ax, tactic in zip(axes, tactics):
        tactic_data = pivot_df[tactic][pivot_df[tactic] > 0]
        num_rows = tactic_data.shape[0]  # Number of non-zero occurrences in this tactic
        if not tactic_data.empty:
            tactic_matrix = tactic_data.values.reshape(-1, 1)
            wrapped_labels = wrap_labels(tactic_data.index.to_series().apply(lambda x: f"{x[0]} - {x[1]}"))

            sns.heatmap(tactic_matrix, annot=np.array(wrapped_labels).reshape(-1, 1), 
                        fmt='', cmap='RdYlGn_r', ax=ax, vmin=vmin, vmax=vmax, cbar=False, annot_kws = {"size":8})
            ax.set_ylim(0, max_rows)  # Set consistent y-axis limits based on max_rows
            ax.invert_yaxis()  # Invert the y-axis to go top to bottom

            # Formatting
            ax.xaxis.set_label_position('top')
            ax.set_xlabel(tactic)
            ax.set_xticks([])  # Remove x-ticks
            ax.set_yticks([])  # Remove y-ticks

    # Adjust layout
    plt.subplots_adjust(wspace=0.1, hspace=0.1, right=0.85)
    fig.suptitle(f"{apt.upper()} Heat Map", fontsize = 20)

    # Add one colorbar for all subplots, using the first subplot as a reference
    cbar_ax = fig.add_axes([0.9, 0.3, 0.02, 0.4])  # Adjust the position as needed
    fig.colorbar(axes[0].collections[0], cax=cbar_ax).set_label('Number of Occurrences')
    pic_name = os.path.join(download, f"{apt.upper()} Heat Map - CAO {date.today()}")
    plt.savefig(pic_name)
    print(f"Image of heat map saved as: {pic_name}")
    # Display the plot
    plt.show()

def choose_id():
    pd.set_option('display.max_rows', None)
    un_dup = apt_data.drop_duplicates(subset='Technique_ID', keep="first")
    un_dup = un_dup.reset_index()
    print(f"{un_dup[['Technique_ID', 'Technique_Name', 'Step']]}")
    print("\n\n\033[1mIf you would like an image of this, it is best to snip it, as I don't want to have it download\033[0m")
    print("\n\n\033[1mOnly way to exit currently is by either exiting the CLI or by click through to the end of the Tree graph\033[0m\n\nWhich can be difficult due to some steps being available at lower stages of an attack and creating a labyrinth of choices")
    id_chosen = input("Please enter tactic (Technique_ID, Index, Name, or Exit to go back to the Main Option menu): ").upper()
    print(f'You entered: {id_chosen}')

    # Check if the input is a Technique_ID
    if id_chosen in apt_data['Technique_ID'].values:
        return id_chosen
    
    # Check if the input is an index
    if id_chosen.isdigit():
        index = int(id_chosen)
        if 0 <= index < len(un_dup):
            return un_dup.loc[index, 'Technique_ID']
        else:
            print("Invalid index.")
            return choose_id(apt_data)
    
    # Check if the input is a Technique_Name
    if id_chosen in un_dup['Technique_Name'].values:
        return un_dup.loc[un_dup['Technique_Name'] == id_chosen, 'Technique_ID'].iloc[0]
    
    if id_chosen == "EXIT":
        return id_chosen

    print('Bad choice, try again')
    return choose_id(apt_data)

# Global variable to store the clicked node information
clicked_node = None
right_click_flag = False
id_chosen = model_data['Technique_ID'][0]
def create_network_tree(id_chosen, initial=False):
    global clicked_node, right_click_flag
    
    def calculate_probabilities(id_chosen):
        id_chose = model_data[model_data['Technique_ID'] == id_chosen]
        reference_value = id_chose['References'].values[0]
        pos_weighted_value = 1.5
        neg_weighted_value = 0.5
        step_value = id_chose['Step'].values[0]
        def weight_cal(reference_value):
            model_data['weight'] = model_data.apply(lambda x: x['Number of Occurances'] * pos_weighted_value if x['References'] == reference_value else x['Number of Occurances'] * neg_weighted_value, axis=1)
            return model_data

        def step_matching(step_value):
            try:
                step_match = model_data[(model_data['Step'] >= step_value) & (model_data['Step'] < step_value + 2)]
                step_match = step_match[step_match['Step'] != step_value]
                return step_match
            except step_value < 14:
                print(f'{id_chosen} is at the last step, no need for probability check of next step')

        weight = weight_cal(reference_value)
        modeled_weight = weight
        next_potential = step_matching(step_value)

        def assign_probabilities(row):
            if row['weight'] >= 1.5:
                alpha = 2 + row['weight']  # Adjust alpha based on 'weight'
                beta = 2
            elif row['weight'] < 1.5:
                alpha = 1 + row['weight']  # Adjust alpha based on 'weight'
                beta = 2
            else:
                return 0.0  # Default probability for rows with other weights

            # Generate a random probability from the Beta distribution
            probability = stats.beta.rvs(alpha, beta)
            return probability

        # Apply the probability assignment function to create a 'Probability' column
        next_potential['Probability'] = next_potential.apply(assign_probabilities, axis=1)

        most_probable = next_potential[next_potential['Probability'] == next_potential['Probability'].max()]
        most_probable = most_probable['Technique_ID'].drop_duplicates(keep = 'last')
        return next_potential, most_probable
    
    # Get next potential steps based on the chosen ID
    next_potential, most_probable = calculate_probabilities(id_chosen)
    if next_potential.empty:
        print("No further steps available from this node.")
        return 

    # Create a directed graph
    G = nx.DiGraph()

    # Add nodes and edges for the initial node and its connections
    G.add_node(id_chosen)
    for _, row in next_potential.iterrows():
        G.add_node(row['Technique_ID'])
        G.add_edge(id_chosen, row['Technique_ID'], probability=row['Probability'])

    # Create a layout for the nodes
    pos = nx.kamada_kawai_layout(G)

    # Prepare labels with ID and Name
    labels = {row['Technique_ID']: f"{row['Technique_ID']}\n{row['Technique_Name']}\nStage: {row['Step']}" for _, row in next_potential.iterrows()}
    
    # Fetch initial node's information from the main dataset
    if initial or id_chosen in apt_data['Technique_ID'].values:
        initial_node_info = apt_data[apt_data['Technique_ID'] == id_chosen].iloc[0]
        labels[id_chosen] = f"{id_chosen}\n{initial_node_info['Technique_Name']}\nStage: {initial_node_info['Step']}"

    # Draw the graph with custom labels and edge labels
    plt.figure(figsize=(12, 10))
    nx.draw(G, pos, with_labels=False, node_size=500, node_color='lightblue', font_size=8, font_color='black')
    nx.draw_networkx_labels(G, pos, labels)

    # Edge labels
    edge_labels = {(u, v): f'P={d["probability"]:.2f}' for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

    # Function to handle mouse click event
    def on_click(event):
        global clicked_node, right_click_flag
        
        # Check if the right mouse button (button 3) is clicked
        if event.button == 3:
            right_click_flag = True
            return

        # Proceed with node selection if it's not a right-click
        if event.inaxes is not None:
            min_distance = float('inf')
            closest_node = None
            for node in G.nodes():
                distance_squared = (pos[node][0] - event.xdata) ** 2 + (pos[node][1] - event.ydata) ** 2
                if distance_squared < min_distance:
                    min_distance = distance_squared
                    closest_node = node

            # If a node is clicked and it's not the initial node
            if closest_node is not None and closest_node != id_chosen:
                clicked_node = closest_node
                plt.close()  # Close the graph

    # Register the event handler
    cid = plt.gcf().canvas.mpl_connect('button_press_event', on_click)

    # Show the plot
    plt.axis('off')
    plt.show()
    # Check if right-click flag is set and close the plot if it is
    if right_click_flag:
        plt.close()
        right_click_flag = False 
    # If a node was clicked, create a new network tree from that node
    if clicked_node:
        create_network_tree(clicked_node)

def get_download_path():
    return os.path.join(os.path.expanduser('~'), 'Downloads')

while True:
    download = get_download_path()
    print("What would you like to do with this groups information? \nAll files exported will be in your Downloads folder!")
    print("1: Export all of the data as a CSV for your own use\n")
    print("2: Create a heatmap of the group and export an image of the heat map\n  Image saved is formated much better than immediate image shown\n")
    print("3: Create a probability network map for you to explore!\n")
    print("0: Exit\n")

    today = date.today()

    choice = input("Enter your choice (One of the Numbers): ")

    if choice == "0":
        break
    elif choice == "1":
        """List of data"""
        print("Which of the following would you like? \n 1: Associated Names \n 2: APT Techniques \n 3: APT Software \n 4: APT Campaign Info \n 5: All information")
        data_choice = input("Enter your choice (One of the Numbers): ")

        if data_choice == "1":
            file_name = os.path.join(download, f"{apt.upper()} Associated_names - CAO {today.csv}")
            associated_names_df.to_csv(file_name)
        elif data_choice == "2":
            file_name = os.path.join(download, f"{apt.upper()} APT Techniques - CAO {today.csv}")
            apt_techniques_df.to_csv(file_name)
        elif data_choice == "3":
            file_name = os.path.join(download, f"{apt.upper()} APT Software - CAO {today.csv}")
            software_df.to_csv(file_name)
        elif data_choice == "4":
            if 'campaigns_df' in locals():
                file_name = os.path.join(download, f"{apt.upper()} Campaigns - CAO {today.csv}")
                campaigns_df.to_csv(file_name)
            else:
                print(f"Campaigns were not available for the selected apt: {apt}")
        elif data_choice == "5":
            file_name = os.path.join(download, f"{apt.upper()} Associated_names - CAO {today}.csv")
            associated_names_df.to_csv(file_name)
            print(file_name)
            file_name = os.path.join(download, f"{apt.upper()} APT Techniques - CAO {today}.csv")
            apt_techniques_df.to_csv(file_name)
            print(file_name)
            file_name = os.path.join(download, f"{apt.upper()} APT Software - CAO {today}.csv")
            software_df.to_csv(file_name)
            print(file_name)
            if 'campaigns_df' in locals():
                file_name = os.path.join(download, f"{apt.upper()} Campaigns - CAO {today}.csv")
                campaigns_df.to_csv(file_name)
                print(file_name)
            else:
                print(f"Campaigns were not available for the selected apt: {apt}")
        else:
            print("Invalid choice")
    elif choice == "2":
        """Heat map of data"""
        heat_map(pivot_df)
    elif choice == "3":
        """Probability Tree"""
        id_chosen = choose_id()
        if id_chosen != "EXIT":
            create_network_tree(id_chosen)
        else:
            pass
    else:
        print("Invalid choice")