"""Generate and print public key for testing
"""

from . import generate_private_key


def main():
    priv = generate_private_key()
    # public key as JSON string representation
    print(repr(priv.export_public(as_dict=False)))


if __name__ == "__main__":
    main()
