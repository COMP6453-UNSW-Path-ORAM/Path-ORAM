import os

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

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
    df["storage_size"] = df["config_storage_size"]  # rename
    df["avg_latency"] = df["total_time"] / df["config_num_operations"]
    return df


def plot_latency_vs_throughput(df):
    plt.figure(figsize=(12, 7))
    g = sns.scatterplot(
        data=df,
        x="throughput",
        y="avg_latency",
        hue="config_use_recursive",
        style="config_use_recursive",
        s=100,
    )
    g.set_title("Latency (time to complete a request) in sec vs. Throughput")
    g.set_xlabel("Throughput", fontsize=12)
    g.set_ylabel("Latency (sec)", fontsize=12)
    g.legend(title="Recursive ORAM")
    plt.tight_layout()
    plt.savefig("plots/latency_vs_throughput.png")
    plt.close()


def plot_throughput_vs_storage_size(df):
    plt.figure(figsize=(12, 7))
    g = sns.lineplot(
        data=df,
        x="storage_size",
        y="throughput",
        hue="config_use_recursive",
        style="config_use_recursive",
        markers=True,
        dashes=False,
        errorbar="sd",
    )
    g.set_title("Throughput vs. ORAM Storage Size")
    g.set_xlabel("Storage Size")
    g.set_ylabel("Throughput (r/w operations/second)")
    g.legend(title="Recursive ORAM")
    g.set_xscale("log")
    plt.tight_layout()
    plt.savefig("plots/throughput_vs_storage_size.png")
    plt.close()


def plot_client_size_vs_storage_size(df):
    plt.figure(figsize=(12, 7))
    g = sns.lineplot(
        data=df,
        x="storage_size",
        y="client_size",
        hue="config_use_recursive",
        style="config_use_recursive",
        markers=True,
        dashes=False,
        errorbar="sd",
    )
    g.set_title("Client-Side Memory Usage vs. ORAM Storage Size")
    g.set_xlabel("Storage Size")
    g.set_ylabel("Client Memory (bytes)")
    g.legend(title="Recursive ORAM")
    g.set_xscale("log")
    plt.yscale("log")
    plt.tight_layout()
    plt.savefig("plots/client_size_vs_storage_size.png")
    plt.close()


def plot_bandwidth_overhead_vs_block_size(df):
    df_fixed_storage = df[df.config_storage_size == 2047]
    plt.figure(figsize=(12, 7))
    g = sns.lineplot(
        data=df_fixed_storage,
        x="config_block_size",
        y="bandwidth_overhead",
        hue="config_use_recursive",
        style="config_use_recursive",
        markers=True,
        dashes=False,
        errorbar="sd",
    )
    g.set_title("Bandwidth Overhead vs. Block Size (storage size = 2047)")
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


def find_best_params(df):
    # usecase - High-Throughput Computing
    # Maximize operations per second
    print("\nUse Case: High-Throughput Computing")
    best_throughput = df.sort_values(by="throughput", ascending=False).iloc[0]
    print(
        best_throughput[
            [
                "config_storage_size",
                "config_block_size",
                "config_blocks_per_bucket",
                "config_use_recursive",
                "throughput",
                "client_size",
                "bandwidth_overhead",
            ]
        ]
    )

    # usecase - Constrained IoT/Mobile Device
    # Minimize client-side memory usage.
    print("\nUse Case: Constrained Device (Minimize Client Memory)")
    best_client_size = df.sort_values(by="client_size", ascending=True).iloc[0]
    print(
        best_client_size[
            [
                "config_storage_size",
                "config_block_size",
                "config_blocks_per_bucket",
                "config_use_recursive",
                "throughput",
                "client_size",
                "bandwidth_overhead",
            ]
        ]
    )

    # usecase - Metered/Slow Network
    # Minimize bandwidth overhead.
    print("\nUse Case: Metered Network (Minimize Bandwidth Overhead)")
    best_bandwidth = df.sort_values(by="bandwidth_overhead", ascending=True).iloc[0]
    print(
        best_bandwidth[
            [
                "config_storage_size",
                "config_block_size",
                "config_blocks_per_bucket",
                "config_use_recursive",
                "throughput",
                "client_size",
                "bandwidth_overhead",
            ]
        ]
    )

    # usecase - Balanced/General Purpose
    # A good mix of throughput, client size, and bandwidth.
    # We create a composite score to rank them. Lower is better.
    print("\nUse Case: Balanced / General Purpose")
    # fix
    balanced_df = df.copy()
    balanced_df["norm_throughput"] = 1 - (
        balanced_df["throughput"] / balanced_df["throughput"].max()
    )
    balanced_df["norm_client_size"] = (
        balanced_df["client_size"] / balanced_df["client_size"].max()
    )
    balanced_df["norm_bandwidth"] = (
        balanced_df["bandwidth_overhead"] / balanced_df["bandwidth_overhead"].max()
    )
    balanced_df["performance_score"] = (
        balanced_df["norm_throughput"]
        + balanced_df["norm_client_size"]
        + balanced_df["norm_bandwidth"]
    )
    best_balanced = balanced_df.sort_values(
        by="performance_score", ascending=True
    ).iloc[0]
    print(
        best_balanced[
            [
                "config_storage_size",
                "config_block_size",
                "config_blocks_per_bucket",
                "config_use_recursive",
                "throughput",
                "client_size",
                "bandwidth_overhead",
                "performance_score",
            ]
        ]
    )


def main():
    df = load_data()
    df = calculate_derived_metrics(df)

    find_best_params(df)

    plot_latency_vs_throughput(df)
    plot_throughput_vs_storage_size(df)
    plot_client_size_vs_storage_size(df)
    plot_bandwidth_overhead_vs_block_size(df)
    analyze_read_write_ratio(df)


if __name__ == "__main__":
    main()
