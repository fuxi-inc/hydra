package identifier

import (
	"github.com/ory/x/errorsx"
)

type Validator struct {
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Validate(jsonTrans *JSONTrans) error {
	if jsonTrans.DataID == "" || jsonTrans.UserID == "" || jsonTrans.DataAddress == "" || jsonTrans.DataDigest == nil || jsonTrans.Sign == nil {
		return errorsx.WithStack(ErrInvalidIdentifierMetadata.WithHint("DataID, UserID, DataAddress, DataDigest, Sign must be set."))
	}
	return nil
}
