import queue
import threading
import time
import random
import statistics
import json
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from itertools import product
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pathoram.client.pathoram_client import ClientOram, ClientOramRecursive
from pathoram.server.pathoram_server import ServerOram
from pathoram.client import ADDRESS_SIZE


@dataclass
class Configuration:
    storage_size: int
    block_size: int
    blocks_per_bucket: int
    recursive_depth: int
    use_recursive: bool
    num_operations: int
    read_write_ratio: float  # 0.0 = all writes, 1.0 = all reads


@dataclass
class Result:
    config: Configuration
    total_time: float
    avg_read_time: float
    avg_write_time: float
    throughput: float  # operations per second
    memory_usage: int
    stash_overflow_count: int
    error_count: int


class Benchmarker:
    """Runs a grid search for finding optimal parameter combination"""

    def __init__(self):
        self.results: List[Result] = []

    def setup_communication(self):
        """Setup communication queues between client and server separately for each benchamrk"""
        client_message_queue: queue.Queue[bytes] = queue.Queue()
        server_message_queue: queue.Queue[bytes] = queue.Queue()
        stop_event = threading.Event()

        def watch_for_messages_server(server_oram: ServerOram) -> None:
            while not stop_event.is_set():
                try:
                    command = server_message_queue.get(timeout=0.1)
                    if not stop_event.is_set():
                        server_oram.process_command(command)

                except queue.Empty:
                    continue

        def send_message_init(
            client_id: bytes, storage_size: int, block_size: int, blocks_per_bucket: int
        ) -> None:
            server_message_queue.put(
                client_id
                + b"I"
                + storage_size.to_bytes(ADDRESS_SIZE, byteorder="big")
                + block_size.to_bytes(ADDRESS_SIZE, byteorder="big")
                + blocks_per_bucket.to_bytes(ADDRESS_SIZE, byteorder="big")
            )
            client_message_queue.get()

        def send_message_read(client_id: bytes, addr: int) -> bytes:
            server_message_queue.put(
                client_id + b"R" + addr.to_bytes(ADDRESS_SIZE, byteorder="big")
            )
            return client_message_queue.get()

        def send_message_write(client_id: bytes, addr: int, message: bytes) -> None:
            server_message_queue.put(
                client_id
                + b"W"
                + addr.to_bytes(ADDRESS_SIZE, byteorder="big")
                + message
            )
            client_message_queue.get()

        def send_message_server(message: bytes) -> None:
            client_message_queue.put(message)

        return (
            client_message_queue,
            server_message_queue,
            stop_event,
            watch_for_messages_server,
            send_message_init,
            send_message_read,
            send_message_write,
            send_message_server,
        )

    def run_benchmark(self, config: Configuration):
        print(
            f"Running benchmark: storage={config.storage_size}, block={config.block_size}, bucket={config.blocks_per_bucket},read/write ratio={config.read_write_ratio}"
        )
        print(
            f"recursive={config.use_recursive},recurcive depth={config.recursive_depth}"
        )

        (
            _,  # client message queue not used
            server_message_queue,
            stop_event,
            watch_for_messages_server,
            send_message_init,
            send_message_read,
            send_message_write,
            send_message_server,
        ) = self.setup_communication()

        key = AESGCM.generate_key(bit_length=256)

        # setup server
        server_oram = ServerOram(send_message_server, key=key)
        server_thread = threading.Thread(
            target=watch_for_messages_server, args=(server_oram,)
        )
        server_thread.start()

        # setup client. only one of the 2 clients is used per benchmark
        if config.use_recursive:
            client_oram = ClientOramRecursive(
                storage_size=config.storage_size,
                send_message_read=send_message_read,
                send_message_write=send_message_write,
                send_message_init=send_message_init,
                recursive_depth=config.recursive_depth,
                block_size=config.block_size,
                blocks_per_bucket=config.blocks_per_bucket,
                key=key,
            )
        else:
            client_oram = ClientOram(
                storage_size=config.storage_size,
                send_message_read=send_message_read,
                send_message_write=send_message_write,
                send_message_init=send_message_init,
                block_size=config.block_size,
                blocks_per_bucket=config.blocks_per_bucket,
                key=key,
            )

        try:
            test_data = {}  # store all data written locally for verification
            # populate oram storage with some starting data
            for i in range(config.storage_size):
                data = random.randbytes(config.block_size)
                test_data[i] = data
                client_oram.write_block(i, data)

            read_times = []
            write_times = []
            error_count = 0
            stash_overflow_count = 0

            start_time = time.time()

            for i in range(config.num_operations):
                address = random.randint(0, config.storage_size - 1)
                try:
                    if random.random() < config.read_write_ratio:
                        op_start = time.time()
                        data = client_oram.read_block(address)
                        read_times.append(time.time() - op_start)

                        # verify data integrity for written blocks
                        if address in test_data and data != test_data[address]:
                            error_count += 1
                    else:
                        data = random.randbytes(config.block_size)
                        op_start = time.time()
                        client_oram.write_block(address, data)
                        write_times.append(time.time() - op_start)
                        test_data[address] = data

                except IndexError as e:
                    if "Bucket overflowed" in str(e):
                        stash_overflow_count += 1
                    error_count += 1
                except Exception as e:
                    print(e)
                    error_count += 1

            total_time = time.time() - start_time

            avg_read_time = statistics.mean(read_times) if read_times else 0
            avg_write_time = statistics.mean(write_times) if write_times else 0
            throughput = config.num_operations / total_time

            # naive calculation, not counting overhead
            memory_usage = (
                config.storage_size * config.blocks_per_bucket * (config.block_size)
            )

            result = Result(
                config=config,
                total_time=total_time,
                avg_read_time=avg_read_time,
                avg_write_time=avg_write_time,
                throughput=throughput,
                memory_usage=memory_usage,
                stash_overflow_count=stash_overflow_count,
                error_count=error_count,
            )
            self.results.append(result)

            print(result)

            return result

        except Exception as e:
            print(e)

        finally:
            stop_event.set()
            server_message_queue.put(b"")
            server_thread.join(timeout=1)

    def run_benchmark_suite(self) -> List[Result]:
        configs = []

        # read_write_ratios = [0.5]

        # storage_sizes = [2047]
        # block_sizes = [64]
        # blocks_per_bucket = [4]

        read_write_ratios = [0.3, 0.5, 0.7]

        storage_sizes = [2**s - 1 for s in range(7, 12)]
        block_sizes = [2**s for s in range(5, 9)]
        blocks_per_bucket = [2, 4, 6, 8]

        # non-resurcive
        for storage, block, bucket, ratio in product(
            storage_sizes,
            block_sizes,
            blocks_per_bucket,
            read_write_ratios,
        ):
            configs.append(
                Configuration(
                    storage_size=storage,
                    block_size=block,
                    blocks_per_bucket=bucket,
                    recursive_depth=0,
                    use_recursive=False,
                    num_operations=storage * bucket,
                    read_write_ratio=ratio,
                )
            )

        # recursive
        # recursive_depths = [1]  # for recursive client only
        recursive_depths = [1, 2, 3, 4]  # for recursive client only
        for storage, block, bucket, depth, ratio in product(
            storage_sizes,
            block_sizes,
            blocks_per_bucket,
            recursive_depths,
            read_write_ratios,
        ):
            configs.append(
                Configuration(
                    storage_size=storage,
                    block_size=block,
                    blocks_per_bucket=bucket,
                    recursive_depth=depth,
                    use_recursive=True,
                    num_operations=storage * bucket,
                    read_write_ratio=ratio,
                )
            )

        print(f"Running {len(configs)} benchmark configurations...")

        for i, config in enumerate(configs):
            print(f"Progress: {i+1}/{len(configs)}")
            try:
                self.run_benchmark(config)
            except Exception as e:
                print(f"Error in benchmark {i+1}: {e}")

        return self.results

    def analyze_results(self) -> Dict[str, Any]:
        return {}

    def generate_report(self, filename: str = "benchmark_report.csv"):
        analysis = self.analyze_results()
        return analysis


def main():
    benchmarker = Benchmarker()
    results = benchmarker.run_benchmark_suite()

    print(f"\nCompleted benchmarks for {len(results)} configs")

    analysis = benchmarker.generate_report()


if __name__ == "__main__":
    main()
