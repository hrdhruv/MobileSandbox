import torch
import numpy as np
from dl_model import MalwareNet

MODEL_PATH = "dl_model.pt"

model = None
optimizer = None
feature_index = None


def load_model(feature_names):
    global model, optimizer, feature_index

    feature_index = {f: i for i, f in enumerate(feature_names)}

    model = MalwareNet(len(feature_names))
    model.load_state_dict(torch.load(MODEL_PATH))
    model.train()

    optimizer = torch.optim.Adam(model.parameters(), lr=0.0001)


def build_feature_vector(active_features):
    x = np.zeros(len(feature_index), dtype=np.float32)
    for f in active_features:
        if f in feature_index:
            x[feature_index[f]] = 1.0
    return torch.tensor(x).unsqueeze(0)


def analyze(features):
    x = build_feature_vector(features)
    with torch.no_grad():
        prob = model(x).item()

    if prob > 0.8:
        level = "DANGEROUS"
    elif prob > 0.4:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    return prob, level


def adaptive_update(features, is_malware):
    x = build_feature_vector(features)
    y = torch.tensor([[1.0 if is_malware else 0.0]])

    pred = model(x)
    loss = torch.nn.functional.binary_cross_entropy(pred, y)

    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
