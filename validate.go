package validate

import (
	"regexp"
	"strconv"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
)

/*
校验统一社会信用代码

统一社会信用代码编码规则

	第1位表示登记管理部门代码（1位字符）
		机构编制 1
		民政 5
		工商 9
		其他 Y

	第2位表示纳税人类别代码（1位字符）
		机构编制机关 1
		机构编制事业单位 2
		机构编制中央编办直接管理机构编制的群众团体 3
		机构编制其他 9

		民政社会团体 1
		民政民办非企业单位 2
		民政基金会 3
		民政其他 9

		工商企业 1
		工商个体工商户 2
		工商农民专业合作社 3

		其他 1

	第3 - 8位表示登记管理机关行政区划码(6位数字)
	第9 - 17位表示主体标识码(组织机构代码, 9位字符)
	第18位表示校验码（1位字符）
*/
func ValidateUSCI(code string) bool {
	if len(code) == 15 {
		return true
	}

	if v, err := regexp.MatchString(`^(11|12|13|19|51|52|53|59|91|92|93|Y1)[0-9]{6}\w{9}\w$`, code); err == nil {
		if !v {
			return false
		}

		// 校验组织机构代码校验码
		organizationCheckCodes := map[string]int{
			"0": 0,
			"1": 1,
			"2": 2,
			"3": 3,
			"4": 4,
			"5": 5,
			"6": 6,
			"7": 7,
			"8": 8,
			"9": 9,
			"A": 10,
			"B": 11,
			"C": 12,
			"D": 13,
			"E": 14,
			"F": 15,
			"G": 16,
			"H": 17,
			"I": 18,
			"J": 19,
			"K": 20,
			"L": 21,
			"M": 22,
			"N": 23,
			"O": 24,
			"P": 25,
			"Q": 26,
			"R": 27,
			"S": 28,
			"T": 29,
			"U": 30,
			"V": 31,
			"W": 32,
			"X": 33,
			"Y": 34,
			"Z": 35,
		}
		stringCodes := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

		factors := []int{3, 7, 9, 10, 5, 8, 4, 2}
		organizationCode := code[8:17]

		checkCode := genCheckCode(organizationCode[:8], factors, 11, organizationCheckCodes)

		switch checkCode {
		case 11:
			checkCode = 0
		case 10:
			checkCode = 33
		}

		if stringCodes[checkCode] != organizationCode[8] {
			return false
		}

		// 校验统一社会信用代码校验码
		// 统一社会信用代码中不使用I, O, S, V, Z
		socialCreditCheckCodes := map[string]int{
			"0": 0,
			"1": 1,
			"2": 2,
			"3": 3,
			"4": 4,
			"5": 5,
			"6": 6,
			"7": 7,
			"8": 8,
			"9": 9,
			"A": 10,
			"B": 11,
			"C": 12,
			"D": 13,
			"E": 14,
			"F": 15,
			"G": 16,
			"H": 17,
			"J": 18,
			"K": 19,
			"L": 20,
			"M": 21,
			"N": 22,
			"P": 23,
			"Q": 24,
			"R": 25,
			"T": 26,
			"U": 27,
			"W": 28,
			"X": 29,
			"Y": 30,
		}
		stringCodes = "0123456789ABCDEFGHJKLMNPQRTUWXY"

		factors = []int{1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28}

		checkCode = genCheckCode(code[:17], factors, 31, socialCreditCheckCodes)

		switch checkCode {
		case 31:
			checkCode = 0
		}

		return stringCodes[checkCode] == code[17]
	}

	return false
}

/*
校验身份证号码

中国居民身份证号码编码规则

	第1 - 2位表示省（直辖市、自治区、特别行政区）

	4个直辖市
		北京 11
		天津 12
		上海 31
		重庆 50

	5个自治区
		内蒙古 15
		广西 45
		西藏 54
		宁夏 64
		新疆 65

	2个特别行政区
		香港特别行政区 810000
		澳门特别行政区 820000

	23个省
		河北省 13
		山西省 14
		辽宁省 21
		吉林省 22
		黑龙江省 23
		江苏省 32
		浙江省 33
		安徽省 34
		福建省 35
		江西省 36
		山东省 37
		河南省 41
		湖北省 42
		湖南省 43
		广东省 44
		海南省 46
		四川省 51
		贵州省 52
		云南省 53
		陕西省 61
		甘肃省 62
		青海省 63
		台湾省 710000

	第3 - 4位表示市（地级市、自治州、盟及国家直辖市所属市辖区和县）
	第5 - 6位表示县（市辖区、县级市、旗）
	第7 - 14位表示出生年月日
	第15 - 17位表示顺序码（奇数为男性, 偶数为女性）
	第18位表示校验码（校验码如果出现数字10, 就用X来代替）
*/
func ValidateIDCard(code string) bool {
	if v, err := regexp.MatchString("^[1-9][0-9]{14}([0-9]{2}[0-9X])$", code); err == nil {
		if !v {
			return false
		}

		// 加权系数
		factors := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

		// 校验码
		checkCodes := []string{"1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"}

		var items []int

		for i := 0; i < len(code)-1; i++ {
			v, _ := strconv.Atoi(string(code[i]))

			items = append(items, v)
		}

		value := 0

		for i := 0; i < len(factors); i++ {
			value += factors[i] * items[i]
		}

		return checkCodes[value%11] == string(code[len(code)-1])
	}

	return false
}

// 校验手机号码
func ValidatePhone(code string) bool {
	if v, err := regexp.MatchString("^1[0-9]{10}$", code); err == nil {
		return v
	}

	return false
}

// 校验建筑编码
func ValidateBuidlingCode(code string) bool {
	if !mapset.NewSet(19, 25).Contains(len(code)) {
		return false
	}

	if strings.Count(code, "T") > 1 {
		return false
	}

	if v, err := regexp.MatchString("^[1-9][0-9T]+$", code); err == nil {
		return v
	}

	return false
}

// 获取校验码
func genCheckCode(code string, factors []int, mode int, checkCodes map[string]int) int {
	var value int

	for i := 0; i < len(code); i++ {
		ch := string(code[i])

		if v, err := strconv.ParseInt(ch, 10, 64); err == nil {
			value += int(v) * factors[i]
		} else {
			value += checkCodes[ch] * factors[i]
		}
	}

	return mode - value%mode
}
