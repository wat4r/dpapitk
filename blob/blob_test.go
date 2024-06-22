package blob

import (
	"reflect"
	"testing"

	"github.com/wat4r/dpapitk/utils"
)

func TestDecryptWithMasterKey(t *testing.T) {
	type args struct {
		blobData  []byte
		masterKey []byte
		entropy   []byte
	}
	var tests = []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "1",
			args: args{
				blobData:  utils.HexToBytes("01000000d08c9ddf0115d1118c7a00c04fc297eb0100000087a856215cf0a649936067af6dc3f607000000000200000000001066000000010000200000007a889361e834dcc1943bc5cbe77d26a652032282f92245eead34cea5d47d0790000000000e800000000200002000000004bbb1910338d48cc4505640242ebf85a6df03a275f4a61391fa8a598bbfa6882000000087dd0562f097d76bbee915803862dba7c4b758bb0eadf2546d6bb3557cc0706c4000000090ef4b760f4d622763bd2530eb7f0c321e468db57e3d49f513a0e41bcc44dce2fed97ab24c58ebde4aa7bdd4e44a1881f85ef35d4513da524b286a04fa5f5f91"),
				masterKey: utils.HexToBytes("681604a380685af5ff5e821ab29e67e679af0405b24f3acdf933eb3f8b7e99b57ab8e502ccddeef27914231ec5dc27de4f84f56917f6163eb5252f45bed6affd"),
				entropy:   nil,
			},
			want: utils.HexToBytes("480065006c006c006f0020004400700061007000690054006b000000"),
		}, {
			name: "2",
			args: args{
				blobData:  utils.HexToBytes("01000000d08c9ddf0115d1118c7a00c04fc297eb0100000087a856215cf0a649936067af6dc3f607000000000200000000001066000000010000200000006956b89b364e1dd99f368a6e9a5781e4c3732774733b15c50fb32750d4a442d6000000000e8000000002000020000000ad7f9d2a2e069e2aa305693e5776653d970c207c7a9fdd130f93faabd70608622000000078cb41ef060298f0a4f1da3ada158c392c47f408be7391b613d3a68fd43ac06f4000000035389c3464c553d89d05d58655150184b69fa9bb3530bb9aae607b0a31d6793508acc5872f28450f5cca5a4ca42d4cd14dc852f2caddaea9a1b4a338639d3ef0"),
				masterKey: utils.HexToBytes("681604a380685af5ff5e821ab29e67e679af0405b24f3acdf933eb3f8b7e99b57ab8e502ccddeef27914231ec5dc27de4f84f56917f6163eb5252f45bed6affd"),
				entropy:   []byte("123456"),
			},
			want: utils.HexToBytes("480065006c006c006f0020004400700061007000690054006b000000"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataBlob := ParseDataBlob(tt.args.blobData)
			got, err := dataBlob.DecryptWithMasterKey(tt.args.masterKey, tt.args.entropy)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptWithMasterKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecryptWithMasterKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}
