#include "../randomx.h"
#include <stdio.h>

int main() {
	const char myKey[] = {
		0xcc, 0xd7, 0xc7, 0x88, 0x9b, 0x39, 0x51, 0x62, 0x50, 0x09, 0x89, 0x14, 0xe3, 0xea, 0xb8, 0xf2, 0xa7, 0x5b, 0x6c, 0xbf, 0xd1, 0x9f, 0x90, 0x66, 0x0d, 0x0c, 0x1b, 0x16, 0xdb, 0xc3, 0xd2, 0x94
	};
	const char myNonce[] = {
		0x16, 0x02, 0x03, 0x00
	};
	const char myInput[] = {
		0x10, 0x10, 0x8e, 0x97, 0xd3, 0xab, 0x06, 0xac, 0x9e, 0x50, 0x57, 0xf7, 0x12, 0x41, 0xf8, 0x80, 0x3f, 0xc2, 0x03, 0x60, 0xf5, 0x7a, 0xa1, 0x1a, 0x3a, 0x51, 0xf4, 0x91, 0xcd, 0x70, 0x86, 0x1d, 0x4b, 0x35, 0xb8, 0x9f, 0x67, 0xef, 0xf6, 
		myNonce[0], myNonce[1], myNonce[2], myNonce[3],
		0x35, 0xff, 0x80, 0x6f, 0xa9, 0xc9, 0x93, 0xb2, 0x89, 0xe9, 0x66, 0xb2, 0x1f, 0x99, 0x7a, 0xe7, 0xde, 0xc9, 0x25, 0x28, 0x21, 0xf6, 0x6c, 0x5c, 0xbf, 0x5e, 0xc2, 0xb8, 0x94, 0xc4, 0x95, 0x31, 0x1b
	};
	char hash[RANDOMX_HASH_SIZE];

	randomx_flags flags = RANDOMX_FLAG_DEFAULT;
	//flags |= RANDOMX_FLAG_HARD_AES;
	//flags |= RANDOMX_FLAG_JIT;
	//flags |= RANDOMX_FLAG_SECURE;
	printf("RANDOMX_FLAG_DEFAULT: %d\n", (flags & RANDOMX_FLAG_DEFAULT) != 0);
	printf("RANDOMX_FLAG_LARGE_PAGES: %d\n", (flags & RANDOMX_FLAG_LARGE_PAGES) != 0);
	printf("RANDOMX_FLAG_HARD_AES: %d\n", (flags & RANDOMX_FLAG_HARD_AES) != 0);
	printf("RANDOMX_FLAG_FULL_MEM: %d\n", (flags & RANDOMX_FLAG_FULL_MEM) != 0);
	printf("RANDOMX_FLAG_JIT: %d\n", (flags & RANDOMX_FLAG_JIT) != 0);
	printf("RANDOMX_FLAG_SECURE: %d\n", (flags & RANDOMX_FLAG_SECURE) != 0);
	printf("RANDOMX_FLAG_ARGON2_SSSE3: %d\n", (flags & RANDOMX_FLAG_ARGON2_SSSE3) != 0);
	printf("RANDOMX_FLAG_ARGON2_AVX2: %d\n", (flags & RANDOMX_FLAG_ARGON2_AVX2) != 0);
	printf("RANDOMX_FLAG_ARGON2: %d\n", (flags & RANDOMX_FLAG_ARGON2) != 0);

	printf("randomx_alloc_cache: start\n");
	randomx_cache *myCache = randomx_alloc_cache(flags);
	printf("randomx_alloc_cache: end\n");

	printf("randomx_init_cache: start\n");
	randomx_init_cache(myCache, &myKey, sizeof myKey);
	printf("randomx_init_cache: end\n");

	printf("randomx_create_vm: start\n");
	randomx_vm *myMachine = randomx_create_vm(flags, myCache, NULL);
	printf("randomx_create_vm: end\n");

	printf("randomx_calculate_hash: start\n");
	randomx_calculate_hash(myMachine, &myInput, sizeof myInput, hash);
	printf("randomx_calculate_hash: end\n");

	printf("randomx_destroy_vm: start\n");
	randomx_destroy_vm(myMachine);
	printf("randomx_destroy_vm: end\n");

	printf("randomx_release_cache: start\n");
	randomx_release_cache(myCache);
	printf("randomx_release_cache: end\n");

	for (unsigned i = 0; i < RANDOMX_HASH_SIZE; ++i) {
		printf("%02x", hash[i] & 0xff);
	}
	printf("\n");

	return 0;
}


/*#[test]
fn valid_test1() {
    let nonce_hex = "16020300"; // 00010110000000100000001100000000
    let nonce_bytes = hex::decode(&nonce_hex).unwrap();
    let nonce = u32::from_be_bytes(nonce_bytes.as_slice().try_into().unwrap());
    let blob_hex = "";
    let mut blob = hex::decode(&blob_hex).unwrap();
    let target_hex = "f3220000";
    let seed_hash_hex = "";
    let seed_hash = hex::decode(seed_hash_hex).unwrap();
    let scaled_target = scale_job_target(target_hex);
    let flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(flags, &seed_hash).unwrap();
    let vm = RandomXVM::new(flags, Some(cache), None).unwrap();
    let job_data = Arc::new(RwLock::new(None));
    let (tx, _rx) = channel();
    let start_nonce = 0;
    let end_nonce = 1;
    let nonce_step = 1;
    let worker_id = String::from("worker1");
    let worker = Worker::new(worker_id, vm, job_data, tx, start_nonce, end_nonce, nonce_step);
    let job_id = String::from("job_id");
    worker.set_job_data(job_id, scaled_target, blob.clone());
    let result = worker.check_nonce(scaled_target, &mut blob, nonce);
    assert!(result.is_some() == true);
    assert_eq!(result.unwrap(), "1cdb8216208d8e06e63154b5be7fffda81d7c6bba0d7a069a87effdf83110000");
}*/