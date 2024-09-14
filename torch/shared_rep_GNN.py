''' A Custom PyTorch Model with Shared representation


'''
import rustworkx as rx
import torch
from torch.nn import nn.Module
import torch.nn.functional as F

# Define Graph embedding
class GraphEmbedding(nn.Module) -> nn.Module:
    def __init(self, input_dim: int, output_dim: int):
        super(GraphEmbedding,self).__init__()
        #Linear transformation
        self.Linear =nn.Linear(input_dim, embed_dim)
        
    def forward(self, graph: rx.PyGraph):
        # Calculate node embeddings
        
        node_embeddings = []
        """ Assume node features are encoded as integers or one-hot vectors.
        Different deep learning embeddings can be experimented with
        """
        for node in graph.nodes():
            node_features = torch.tensor([node], dtype=torch.float32) 
            node_embeddings.append(node_features)
        
        # Stack all node embeddings into a single tensor and compute the mean
        #@TODO: Why:
        node_embeddings = torch.stack(node_embeddings, dim=0)
        graph_embedding = torch.mean(node_embeddings, dim=0)
        
        # Pass through the linear layer to get the final embedding
        return self.linear(graph_embedding)

# Now we integrate this GraphEmbedding layer into your threat analysis pipeline
class EnhancedGraphClassifier(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int, output_dim: int, graph_embed_dim: int):
        super(EnhancedGraphClassifier, self).__init__()
        # Initialize graph embedding layer
        self.graph_embedding = GraphEmbedding(input_dim=input_dim, embed_dim=graph_embed_dim)
        
        # Linear layer for final classification
        self.linear = nn.Linear(graph_embed_dim, hidden_dim)
        
        # Other layers (Conv2D, GAT, etc.) similar to the previous example
        self.conv1 = nn.Conv2d(in_channels=1, out_channels=16, kernel_size=(3, 3))
        self.relu1 = nn.ReLU()
        self.conv2 = nn.Conv2d(in_channels=16, out_channels=32, kernel_size=(3, 3))
        self.relu2 = nn.ReLU()
        self.classifier = nn.Linear(hidden_dim, output_dim)
        self.sigmoid = nn.Sigmoid()

    def forward(self, graph: rx.PyGraph, x: torch.Tensor, adj: torch.Tensor):
        # Generate graph embedding from rustworkx graph
        graph_embed = self.graph_embedding(graph)
        
        # Pass the embedding through a linear layer
        x = self.linear(graph_embed).unsqueeze(1)
        
        # Apply Conv2D layers
        x = self.relu1(self.conv1(x))
        x = self.relu2(self.conv2(x))
        
        # Final classification and sigmoid activation
        output = self.sigmoid(self.classifier(x))
        
        return output

# Usage
def main():
    # Initialize the graph
    graph = rx.PyGraph()
    
    # Add nodes and edges to the graph (simplified example)
    graph.add_nodes_from([0, 1, 2])
    graph.add_edges_from([(0, 1), (1, 2)])
    
    # Initialize model
    input_dim = 10  # Size of the input node features
    hidden_dim = 32  # Size of hidden layer
    output_dim = 1  # Binary classification (0/1 for threat)
    graph_embed_dim = 16  # Size of the graph embedding
    
    model = EnhancedGraphClassifier(input_dim, hidden_dim, output_dim, graph_embed_dim)
    
    # Example inputs
    adj = torch.rand((3, 3))  # Placeholder adjacency matrix
    x = torch.rand((3, input_dim))  # Placeholder node features
    
    # Forward pass through the model
    output = model(graph, x, adj)
    print("Output:", output)

if __name__ == "__main__":
    main()