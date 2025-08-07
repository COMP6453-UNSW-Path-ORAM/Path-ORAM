import pandas as pd
from matplotlib import pyplot


def main():
    with open("results.csv") as f:
        df = pd.read_csv(f)

    # memory utilization with default parameters
    # comparison between recursive and non-recursive
    read_write_ratio = 0.5
    storage_size = 2047
    block_size = 64
    blocks_per_bucket = 4
    default_recursive_df = df[
        (df.config_read_write_ratio == read_write_ratio)
        & (df.config_storage_size == storage_size)
        & (df.config_block_size == block_size)
        & (df.config_blocks_per_bucket == blocks_per_bucket)
        & (df.config_use_recursive == True)
    ]
    default_non_recursive_df = df[
        (df.config_read_write_ratio == read_write_ratio)
        & (df.config_storage_size == storage_size)
        & (df.config_block_size == block_size)
        & (df.config_blocks_per_bucket == blocks_per_bucket)
        & (df.config_use_recursive == False)
    ]

    print(
        f"recursive client map size: {default_recursive_df.iloc[0].client_position_map_size} bytes"
    )
    print(
        f"non-recursive client map size: {default_non_recursive_df.iloc[0].client_position_map_size} bytes"
    )


if __name__ == "__main__":
    main()
