package masterkey

import (
	"reflect"
	"testing"

	"github.com/wat4r/dpapitk/utils"
)

func TestInitMasterKeyFile(t *testing.T) {
	type args struct {
		masterKeyFileData []byte
	}
	tests := []struct {
		name string
		args args
		want []byte // MasterKeyFile.MasterKey.PbKey
	}{
		{
			name: "Workgroup master key file parse",
			args: args{
				masterKeyFileData: utils.HexToBytes("020000000000000000000000650061003800300064003500340037002d0038003600380063002d0034006600630033002d0038003300630066002d003000370032003000330033003300300064003300620065000000e973f401000005000000b000000000000000900000000000000014000000000000000000000000000000020000004918b72a66521ddc035d19f53310f624401f00000e80000010660000990fd5bd486feca8792e554c187183a6f976ef981272d86129ef7e681ff59646d8ec3194c64bc5b7e355f225260f5f5d5ad9ad6b05eceb06c504159e7e604ede5f20ce2bd4871041d0d0be5905b7fbd4cc0170f34f498718f45d3e4bf7c4f2d123973028db6d7306824f57db854d52c385ddfb4feca09c2e3cecad91b1cecfa87453dadd04dc8e68f5e176743854046d020000006bd8d14cc9aa8eee24cbc0fc730334b9401f00000e800000106600009ed4e154212a47cefb1f3c02aa3ba76ef70e12396dcd27571bf448ae64dc8b40bcbf6e5cdda27a8ab3eac1eb559f39da15375572a143bb031445bd9c042569c61df7af1e62966537a789b043b5b0f71f15463316d8489006cd01dca03c73a95df0dbdcff597883b9e6f6e6f6914f140803000000cc9a3955c12ec844ba4c88dfb136c1f8"),
			},
			want: utils.HexToBytes("990fd5bd486feca8792e554c187183a6f976ef981272d86129ef7e681ff59646d8ec3194c64bc5b7e355f225260f5f5d5ad9ad6b05eceb06c504159e7e604ede5f20ce2bd4871041d0d0be5905b7fbd4cc0170f34f498718f45d3e4bf7c4f2d123973028db6d7306824f57db854d52c385ddfb4feca09c2e3cecad91b1cecfa87453dadd04dc8e68f5e176743854046d"),
		},
		{
			name: "Domain master key file parse",
			args: args{
				masterKeyFileData: utils.HexToBytes("020000000000000000000000360065003900300039006500330035002d0038003400300062002d0034003200310061002d0038003400360030002d0062003600630061003700660031003000360065003500380000005ab9f101000000000000880000000000000068000000000000000000000000000000740100000000000002000000f2ff62e9a581ad6ad2f5f88510790ffd50460000098000000366000019a1b6ee8a19a9d921bec803256e5fe168bb2cd026217b2be1fd1b49a1b000acf04893fe3721bc016acbe7189ba3220438f206bbbcc81ddb3c4100c225b538eb40a0a1677918b71e7dd43a371f46fc785b2b3b60b33c806a3c3e1cae5578179e6866272bcb02d35b0200000087ace41af167dad4e2481d0953e90aa750460000098000000366000061de696181f9d5bcc7247591b48faabae9c4652c5f738936a9a777e679fdf98646d505584776790dc64ce79e9b6c99b79c526f373d4f93497f3433137e1270c733d53397d29c39c902000000000100005800000022637588f64c214e93da989c09c3d18cd5bd1f08a3818da740924235a08a402915af4fdcead3088f496d905a968a3f1836adba3b05550f552bb3177a956a934652f14e0f8c85a29b1d3724019ce4bd0e0de493df5cbe1279fe9f616bed2281034c3b80758c89304b074f27018336d3b54e58887594c7271945371adf81ee21ceb06047e72eed0de97b64101609918645175848105735006604b126eae518331fa1e2a940bca18376955b666cd4f2e8438f527fc5d147f7fe3a1878a02a74cc66028d64a7641964fe510e76c7dc9db2826b162b7a973214d1b63aaab536f6292df4c6ab29df55a9519981ea1f6c4084c6af06177039e6b72393bfcf7261ffec89ab10092575055b77e86931d431acbe111b605c71464c71418c72ef9a8dd610e59f876d919d87b9acfa45a27ca526b4967a0b8d564d14da9e49d83a46c43282952e497b7738ccbd0bbd51ecc15dcfcd6d95e74ec8ef3eef6fe16344c08b1dd48f67d8a8b6a7d08a19"),
			},
			want: utils.HexToBytes("19a1b6ee8a19a9d921bec803256e5fe168bb2cd026217b2be1fd1b49a1b000acf04893fe3721bc016acbe7189ba3220438f206bbbcc81ddb3c4100c225b538eb40a0a1677918b71e7dd43a371f46fc785b2b3b60b33c806a3c3e1cae5578179e6866272bcb02d35b"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InitMasterKeyFile(tt.args.masterKeyFileData); !reflect.DeepEqual(got.MasterKey.PbKey, tt.want) {
				t.Errorf("InitMasterKeyFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMasterKeyFile_DecryptWithPassword(t *testing.T) {
	type args struct {
		userSID  string
		password string
	}
	tests := []struct {
		name          string
		masterKeyFile MasterKeyFile
		args          args
		want          bool
	}{
		{
			name:          "Workgroup master key file decrypt with password",
			masterKeyFile: InitMasterKeyFile(utils.HexToBytes("020000000000000000000000650061003800300064003500340037002d0038003600380063002d0034006600630033002d0038003300630066002d003000370032003000330033003300300064003300620065000000e973f401000005000000b000000000000000900000000000000014000000000000000000000000000000020000004918b72a66521ddc035d19f53310f624401f00000e80000010660000990fd5bd486feca8792e554c187183a6f976ef981272d86129ef7e681ff59646d8ec3194c64bc5b7e355f225260f5f5d5ad9ad6b05eceb06c504159e7e604ede5f20ce2bd4871041d0d0be5905b7fbd4cc0170f34f498718f45d3e4bf7c4f2d123973028db6d7306824f57db854d52c385ddfb4feca09c2e3cecad91b1cecfa87453dadd04dc8e68f5e176743854046d020000006bd8d14cc9aa8eee24cbc0fc730334b9401f00000e800000106600009ed4e154212a47cefb1f3c02aa3ba76ef70e12396dcd27571bf448ae64dc8b40bcbf6e5cdda27a8ab3eac1eb559f39da15375572a143bb031445bd9c042569c61df7af1e62966537a789b043b5b0f71f15463316d8489006cd01dca03c73a95df0dbdcff597883b9e6f6e6f6914f140803000000cc9a3955c12ec844ba4c88dfb136c1f8")),
			args: args{
				userSID:  "S-1-5-21-3461634040-4115545689-1944680405-500",
				password: "abc@123",
			},
			want: true,
		},
		{
			name:          "Domain master key file decrypt with password",
			masterKeyFile: InitMasterKeyFile(utils.HexToBytes("020000000000000000000000360065003900300039006500330035002d0038003400300062002d0034003200310061002d0038003400360030002d0062003600630061003700660031003000360065003500380000005ab9f101000000000000880000000000000068000000000000000000000000000000740100000000000002000000f2ff62e9a581ad6ad2f5f88510790ffd50460000098000000366000019a1b6ee8a19a9d921bec803256e5fe168bb2cd026217b2be1fd1b49a1b000acf04893fe3721bc016acbe7189ba3220438f206bbbcc81ddb3c4100c225b538eb40a0a1677918b71e7dd43a371f46fc785b2b3b60b33c806a3c3e1cae5578179e6866272bcb02d35b0200000087ace41af167dad4e2481d0953e90aa750460000098000000366000061de696181f9d5bcc7247591b48faabae9c4652c5f738936a9a777e679fdf98646d505584776790dc64ce79e9b6c99b79c526f373d4f93497f3433137e1270c733d53397d29c39c902000000000100005800000022637588f64c214e93da989c09c3d18cd5bd1f08a3818da740924235a08a402915af4fdcead3088f496d905a968a3f1836adba3b05550f552bb3177a956a934652f14e0f8c85a29b1d3724019ce4bd0e0de493df5cbe1279fe9f616bed2281034c3b80758c89304b074f27018336d3b54e58887594c7271945371adf81ee21ceb06047e72eed0de97b64101609918645175848105735006604b126eae518331fa1e2a940bca18376955b666cd4f2e8438f527fc5d147f7fe3a1878a02a74cc66028d64a7641964fe510e76c7dc9db2826b162b7a973214d1b63aaab536f6292df4c6ab29df55a9519981ea1f6c4084c6af06177039e6b72393bfcf7261ffec89ab10092575055b77e86931d431acbe111b605c71464c71418c72ef9a8dd610e59f876d919d87b9acfa45a27ca526b4967a0b8d564d14da9e49d83a46c43282952e497b7738ccbd0bbd51ecc15dcfcd6d95e74ec8ef3eef6fe16344c08b1dd48f67d8a8b6a7d08a19")),
			args: args{
				userSID:  "S-1-5-21-3461634040-4115545689-1944680405-500",
				password: "abc@123",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.masterKeyFile.DecryptWithPassword(tt.args.userSID, tt.args.password)
			if got := tt.masterKeyFile.Decrypted; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecryptWithPassword(); masterKeyFile.Decrypted = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMasterKeyFile_DecryptWithHash(t *testing.T) {
	type args struct {
		userSID string
		hash    string
	}
	tests := []struct {
		name          string
		masterKeyFile MasterKeyFile
		args          args
		want          bool
	}{
		{
			name:          "Workgroup master key file decrypt with sha1 hash",
			masterKeyFile: InitMasterKeyFile(utils.HexToBytes("020000000000000000000000650061003800300064003500340037002d0038003600380063002d0034006600630033002d0038003300630066002d003000370032003000330033003300300064003300620065000000e973f401000005000000b000000000000000900000000000000014000000000000000000000000000000020000004918b72a66521ddc035d19f53310f624401f00000e80000010660000990fd5bd486feca8792e554c187183a6f976ef981272d86129ef7e681ff59646d8ec3194c64bc5b7e355f225260f5f5d5ad9ad6b05eceb06c504159e7e604ede5f20ce2bd4871041d0d0be5905b7fbd4cc0170f34f498718f45d3e4bf7c4f2d123973028db6d7306824f57db854d52c385ddfb4feca09c2e3cecad91b1cecfa87453dadd04dc8e68f5e176743854046d020000006bd8d14cc9aa8eee24cbc0fc730334b9401f00000e800000106600009ed4e154212a47cefb1f3c02aa3ba76ef70e12396dcd27571bf448ae64dc8b40bcbf6e5cdda27a8ab3eac1eb559f39da15375572a143bb031445bd9c042569c61df7af1e62966537a789b043b5b0f71f15463316d8489006cd01dca03c73a95df0dbdcff597883b9e6f6e6f6914f140803000000cc9a3955c12ec844ba4c88dfb136c1f8")),
			args: args{
				userSID: "S-1-5-21-3461634040-4115545689-1944680405-500",
				hash:    "4a8320ced737e03321209bda0cb2e362251ccca7", // sha1 hash
			},
			want: true,
		},
		{
			name:          "Domain master key file decrypt with ntlm hash",
			masterKeyFile: InitMasterKeyFile(utils.HexToBytes("020000000000000000000000360065003900300039006500330035002d0038003400300062002d0034003200310061002d0038003400360030002d0062003600630061003700660031003000360065003500380000005ab9f101000000000000880000000000000068000000000000000000000000000000740100000000000002000000f2ff62e9a581ad6ad2f5f88510790ffd50460000098000000366000019a1b6ee8a19a9d921bec803256e5fe168bb2cd026217b2be1fd1b49a1b000acf04893fe3721bc016acbe7189ba3220438f206bbbcc81ddb3c4100c225b538eb40a0a1677918b71e7dd43a371f46fc785b2b3b60b33c806a3c3e1cae5578179e6866272bcb02d35b0200000087ace41af167dad4e2481d0953e90aa750460000098000000366000061de696181f9d5bcc7247591b48faabae9c4652c5f738936a9a777e679fdf98646d505584776790dc64ce79e9b6c99b79c526f373d4f93497f3433137e1270c733d53397d29c39c902000000000100005800000022637588f64c214e93da989c09c3d18cd5bd1f08a3818da740924235a08a402915af4fdcead3088f496d905a968a3f1836adba3b05550f552bb3177a956a934652f14e0f8c85a29b1d3724019ce4bd0e0de493df5cbe1279fe9f616bed2281034c3b80758c89304b074f27018336d3b54e58887594c7271945371adf81ee21ceb06047e72eed0de97b64101609918645175848105735006604b126eae518331fa1e2a940bca18376955b666cd4f2e8438f527fc5d147f7fe3a1878a02a74cc66028d64a7641964fe510e76c7dc9db2826b162b7a973214d1b63aaab536f6292df4c6ab29df55a9519981ea1f6c4084c6af06177039e6b72393bfcf7261ffec89ab10092575055b77e86931d431acbe111b605c71464c71418c72ef9a8dd610e59f876d919d87b9acfa45a27ca526b4967a0b8d564d14da9e49d83a46c43282952e497b7738ccbd0bbd51ecc15dcfcd6d95e74ec8ef3eef6fe16344c08b1dd48f67d8a8b6a7d08a19")),
			args: args{
				userSID: "S-1-5-21-3461634040-4115545689-1944680405-500",
				hash:    "aa647b916a1fad374df9c30711d58a7a", // ntlm hash
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.masterKeyFile.DecryptWithHash(tt.args.userSID, tt.args.hash)
			if got := tt.masterKeyFile.Decrypted; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecryptWithHash(); masterKeyFile.Decrypted = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMasterKeyFile_DecryptWithPvk(t *testing.T) {
	type args struct {
		pvkFileData []byte
	}
	tests := []struct {
		name          string
		masterKeyFile MasterKeyFile
		args          args
		want          bool
	}{
		{
			name:          "Domain master key file decrypt with domain backup key",
			masterKeyFile: InitMasterKeyFile(utils.HexToBytes("020000000000000000000000360065003900300039006500330035002d0038003400300062002d0034003200310061002d0038003400360030002d0062003600630061003700660031003000360065003500380000005ab9f101000000000000880000000000000068000000000000000000000000000000740100000000000002000000f2ff62e9a581ad6ad2f5f88510790ffd50460000098000000366000019a1b6ee8a19a9d921bec803256e5fe168bb2cd026217b2be1fd1b49a1b000acf04893fe3721bc016acbe7189ba3220438f206bbbcc81ddb3c4100c225b538eb40a0a1677918b71e7dd43a371f46fc785b2b3b60b33c806a3c3e1cae5578179e6866272bcb02d35b0200000087ace41af167dad4e2481d0953e90aa750460000098000000366000061de696181f9d5bcc7247591b48faabae9c4652c5f738936a9a777e679fdf98646d505584776790dc64ce79e9b6c99b79c526f373d4f93497f3433137e1270c733d53397d29c39c902000000000100005800000022637588f64c214e93da989c09c3d18cd5bd1f08a3818da740924235a08a402915af4fdcead3088f496d905a968a3f1836adba3b05550f552bb3177a956a934652f14e0f8c85a29b1d3724019ce4bd0e0de493df5cbe1279fe9f616bed2281034c3b80758c89304b074f27018336d3b54e58887594c7271945371adf81ee21ceb06047e72eed0de97b64101609918645175848105735006604b126eae518331fa1e2a940bca18376955b666cd4f2e8438f527fc5d147f7fe3a1878a02a74cc66028d64a7641964fe510e76c7dc9db2826b162b7a973214d1b63aaab536f6292df4c6ab29df55a9519981ea1f6c4084c6af06177039e6b72393bfcf7261ffec89ab10092575055b77e86931d431acbe111b605c71464c71418c72ef9a8dd610e59f876d919d87b9acfa45a27ca526b4967a0b8d564d14da9e49d83a46c43282952e497b7738ccbd0bbd51ecc15dcfcd6d95e74ec8ef3eef6fe16344c08b1dd48f67d8a8b6a7d08a19")),
			args: args{
				pvkFileData: utils.HexToBytes("1ef1b5b000000000010000000000000000000000940400000702000000a40000525341320008000001000100f1d202746909c160bc8580bebc1e436393b02430c429bde50058a5a0c5bb50e4a9978ffc3ab27513ddd744750146184c9ba31893deb86badc53025cd54e4a160dfcfab0b236e31d58378785b099e8331151af28f4535b4e7871d75dac5f981de04a08790eb156345caa97c6a5c92ef8478c7193507241cb01ea01aed7adf5f0248073b1d945cbd489ba34ccc1a6f49c13c175a5fe65fca31a5429c5f85476d0fe1f1f85dab5b78eb4f315b506c0976af40c0ec5dbb1576ee2ad362456373af70bf05acf32dd03e0f9e2b7df76a40b7c0627f6785a088df9e295d33bb6ad87449df9017f133e73b7a5fd1958650aad3485e4a810198c792dd1aa8f9931b9f72cbb5efdf716172d3795fe223dd2ac9610b2b8c07bb09da7f00c9cc7ce742a8ef56b65df0727bb6884d786f2641312574eab6ee920d1e3cc3b0b7ea83042ecf3aece461d52df3773d52cb1afad856a9fa741542fe33db63daa941523f63cd2f0c09cf8b7037340e48d3f9982d6a54db2cd629222a05f8a12ad81074bd3bbda695d4cdc355552a12dc00ecc86353a12e0209459b1b84526b785201367811ceb730792222f4355473e355a42cf422c7c5dc9859866ae208e3462a4c686e31ad9e5e2f20a12ca9d94ee68d6ee81282121a762866fbfc2f1b9b92cefd57f774e2b1230aff53fd7eb76c847faa847eae2dd123beb04c34e85399a62ef73e1ceb3047fff4550c9a9b228723b07c451152aef818505218452a998fb5d222f50c9f23263b37b055290e0df944616db8d888635cd6129a5bd15585820ef4d5619360cdceb3e2f47eef288151519dd18a047f0936085836b70803eb6003edd43f62234ea0e0242cf3d6bb3046298e8b379fa4762ec06ecfad23aee00d7400980c8137570c470cddcc3d96b38e44e2fc012d9b7037bfd2f6db951c5a3a0739a374e8e1f9a95dd056172dc1fe82e0fd012eefdce7ec34dd1413163974268ad4bfc8286219c6c8e056ccf372788ab35ef198c0371cf50508353ea37ca9a628172569b7e3f2e44be31f0435696433596ef0bc3b5bbadd97aaee420371673b56526f57face640fcddbb6d3ac0c8c63437a6408cce066d8c92c73af1b6f20f0b80b016c8259b564df98a9ee46d231b375e997b7072af231426984bfd702b36a413c4901c5284b9d0eb889cbd0ae0201d108ffa8651df95a1a063ee77a1b7eedac11789d99cfcafa7f41353b7d7ff84911a72109e7f55a297932e70f8d7724d31c71799969e14b4ba190b53947e2f8132597feca1e928e67c9b5daa4a1e137be3eca4280f06bc6a9dc32fffc74cba0cf8fbbd01eac62a2515299c9de9527e2870aff33f4c89a7f99d6d4203fee5c0674f06ab826afde0976d37ec5a3ff8e18ce62e4110c59e9302ec3eb87699c64472996b6b936574f7f550ac12a11d3adc1f7375ba863c8e26a364471ce80899ac45ae0d71e26505520b14280c8869fed08dc0303571c0839aa826bc4d0a1853799c76f47baed1b8c20e042f417b99402f65acb3ae4f542147add53811f7a970831e3dbb2e327da635b906cbd0d647721057b40bfbe2174c12eb4ce3c5d6eb64de45f5439aed9448b1e04c8a4130430a5d563f91c619230a525e7ee01"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.masterKeyFile.DecryptWithPvk(tt.args.pvkFileData)
			if got := tt.masterKeyFile.Decrypted; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecryptWithPvk(); masterKeyFile.Decrypted = %v, want %v", got, tt.want)
			}
		})
	}
}
