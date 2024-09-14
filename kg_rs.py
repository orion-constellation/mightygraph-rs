'''
Rusworkx Graph Generator Using the Veris V > Stix2.1 (V) Mappings



'''
import rustworkx as rx
import numpy as np
from community import community_louvain
from typing import List, Tuple

def create_knowledge_graph() -> rx.PyGraph:
    
    G = rx.PyGraph
    num_nodes = 1000 #@TODO CHANGE depending on fnal number
    G.add_nodes_from(range(num_nodes))