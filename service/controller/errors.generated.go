package controller

import "github.com/xtls/xray-core/common/errors"

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
