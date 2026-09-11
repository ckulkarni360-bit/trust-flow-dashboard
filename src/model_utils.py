"""
model_utils.py

A small MLP (implemented via sklearn's MLPClassifier with partial_fit) used
as the local/global model in the federated setup. sklearn's MLP exposes its
weights as plain numpy arrays (coefs_, intercepts_), which is exactly what
Flower's NumPyClient needs to exchange -- no need for PyTorch/TensorFlow.
"""

import numpy as np
from sklearn.neural_network import MLPClassifier

HIDDEN_LAYER_SIZES = (32, 16)
CLASSES = np.array([0, 1])


def build_model(random_state=42) -> MLPClassifier:
    """Build and return an untrained MLP classifier with fixed architecture.

    :param random_state: Seed for reproducibility.
    :returns: An untrained sklearn MLP with warm_start enabled for
        incremental partial_fit training.
    """
    return MLPClassifier(
        hidden_layer_sizes=HIDDEN_LAYER_SIZES,
        activation="relu",
        solver="adam",
        alpha=1e-4,
        learning_rate_init=1e-3,
        max_iter=1,       # we drive training manually via partial_fit per round
        warm_start=True,
        random_state=random_state,
    )


def init_architecture(model: MLPClassifier, X_sample: np.ndarray, y_sample: np.ndarray):
    """Must be called once before get/set_weights will work -- this is what
    allocates model.coefs_ / model.intercepts_ with the right shapes.

    :param model: The model to initialise.
    :param X_sample: Small feature matrix (>= 1 row) used to trigger
        weight allocation via partial_fit.
    :param y_sample: Corresponding labels; must contain both classes
        (0 and 1) so MLP initialises all output neurons.
    :returns: The same model instance, now with coefs_ and
        intercepts_ allocated.
    """
    model.partial_fit(X_sample, y_sample, classes=CLASSES)
    return model


def get_weights(model: MLPClassifier) -> list[np.ndarray]:
    """Flatten coefs_ + intercepts_ into a single list of ndarrays (Flower's
    Parameters format). The split point (len(model.coefs_)) is fixed by the
    architecture, so set_weights can always unambiguously reverse this.

    :param model: A fitted/initialised MLP model.
    :returns: Copies of all weight arrays (coefs_ then intercepts_).
    """
    return [w.copy() for w in model.coefs_] + [b.copy() for b in model.intercepts_]


def set_weights(model: MLPClassifier, weights: list[np.ndarray]):
    """Overwrite the model's coefs_ and intercepts_ with *weights*.

    :param model: A previously initialised MLP model.
    :param weights: Weight arrays in the order produced by
        :func:`get_weights` (coefs_ first, then intercepts_).
    """
    n_layers = len(model.coefs_)  # architecture already initialized
    model.coefs_ = [w.copy() for w in weights[:n_layers]]
    model.intercepts_ = [b.copy() for b in weights[n_layers:]]


def local_train(model: MLPClassifier, X, y, epochs: int = 1):
    """Run *epochs* passes of partial_fit on the model.

    :param model: The model to train (modified in place).
    :param X: Feature matrix.
    :param y: Label array.
    :param epochs: Number of full passes over X/y.
    :returns: The same model instance after training.
    """
    for _ in range(epochs):
        model.partial_fit(X, y)
    return model


def flatten_weights(weights: list[np.ndarray]) -> np.ndarray:
    """Concatenate all weight arrays into a single 1-D vector.

    :param weights: List of weight arrays (e.g. from
        :func:`get_weights`).
    :returns: A 1-D array containing all weights concatenated.
    """
    return np.concatenate([w.flatten() for w in weights])
