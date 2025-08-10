import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os

sns.set_theme(style="whitegrid")
if not os.path.exists("plots"):
    os.makedirs("plots")


def load_data(filename="results.csv"):
    try:
        df = pd.read_csv(filename)
        print(f"Successfully loaded {filename} with {len(df)} rows.")
        return df
    except FileNotFoundError:
        print(f"Error: '{filename}' not found. Run benchmark.py first.")
        exit()


def calculate_derived_metrics(df):
    # total bandwidth used
    df["total_bandwidth"] = df["bytes_sent_by_client"] + df["bytes_sent_by_server"]
    # total useful information transferred
    df["total_information"] = df["bytes_read"] + df["bytes_written"]
    # overhead ratio, lower is better
    df["bandwidth_overhead"] = df["total_bandwidth"] / df["total_information"]
    df["log2_storage_size"] = np.log2(df["config_storage_size"] + 1)
    return df


def plot_throughput_vs_storage_size(df):
    plt.figure(figsize=(12, 7))
    g = sns.lineplot(
        data=df,
        x="log2_storage_size",
        y="throughput",
        hue="config_use_recursive",
        style="config_use_recursive",
        markers=True,
        dashes=False,
        errorbar="sd",
    )
    g.set_title("Throughput vs. ORAM Storage Size")
    g.set_xlabel("Log2(Storage Size)")
    g.set_ylabel("Throughput (r/w operations/second)")
    g.legend(title="Recursive ORAM")
    plt.tight_layout()
    plt.savefig("plots/throughput_vs_storage_size.png")
    plt.close()


def plot_client_size_vs_storage_size(df):
    plt.figure(figsize=(12, 7))
    g = sns.lineplot(
        data=df,
        x="log2_storage_size",
        y="client_size",
        hue="config_use_recursive",
        style="config_use_recursive",
        markers=True,
        dashes=False,
        errorbar="sd",
    )
    g.set_title("Client-Side Memory Usage vs. ORAM Storage Size")
    g.set_xlabel("Log2(Storage Size)")
    g.set_ylabel("Client Memory (bytes)")
    g.legend(title="Recursive ORAM")
    plt.yscale("log")
    plt.tight_layout()
    plt.savefig("plots/client_size_vs_storage_size.png")
    plt.close()


def plot_bandwidth_overhead_vs_block_size(df):
    plt.figure(figsize=(12, 7))
    g = sns.lineplot(
        data=df,
        x="config_block_size",
        y="bandwidth_overhead",
        hue="config_use_recursive",
        style="config_use_recursive",
        markers=True,
        dashes=False,
        errorbar="sd",
    )
    g.set_title("Bandwidth Overhead vs. Block Size (lower is better)")
    g.set_xlabel("Block Size (bytes)")
    g.set_ylabel("Bandwidth Overhead (transmitted bytes / information bytes)")
    g.legend(title="Recursive ORAM")
    plt.tight_layout()
    plt.savefig("plots/bandwidth_overhead_vs_block_size.png")
    plt.close()


def analyze_read_write_ratio(df):
    df_melted = df.melt(
        id_vars=["config_read_write_ratio", "config_use_recursive"],
        value_vars=["avg_read_time", "avg_write_time"],
        var_name="operation_type",
        value_name="latency",
    )

    plt.figure(figsize=(12, 7))
    g = sns.catplot(
        data=df_melted,
        x="config_read_write_ratio",
        y="latency",
        hue="operation_type",
        col="config_use_recursive",
        kind="bar",
        height=6,
        aspect=1,
    )
    g.figure.suptitle("Latency vs. Read/Write Ratio")
    g.set_axis_labels("Read/Write Ratio", "Average Latency (s)")
    g.set_titles("Recursive ORAM: {col_name}")
    plt.tight_layout()
    plt.savefig("plots/latency_vs_read_write_ratio.png")
    plt.close()


def main():
    df = load_data()
    df = calculate_derived_metrics(df)

    plot_throughput_vs_storage_size(df)
    plot_client_size_vs_storage_size(df)
    plot_bandwidth_overhead_vs_block_size(df)
    analyze_read_write_ratio(df)


if __name__ == "__main__":
    main()
