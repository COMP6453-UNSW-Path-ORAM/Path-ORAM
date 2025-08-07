import pandas as pd


def main():
    with open("results.csv", "r") as f:
        df = pd.read_csv(f)
    df = df[df["error_count"] == 0]
    print(df)


if __name__ == "__main__":
    main()
