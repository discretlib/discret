use std::collections::HashMap;

use crate::security::base64_decode;

use super::{Error, ParamValue, VariableType};

use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "database/query_language/parameter.pest"]
struct PestParser;

#[derive(Debug)]
pub struct Variable {
    name: String,
    var_type: VariableType,
}

#[derive(Debug)]
pub struct Variables {
    vars: HashMap<String, Variable>,
}
impl Default for Variables {
    fn default() -> Self {
        Variables::new()
    }
}
impl Variables {
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
        }
    }

    pub fn add(&mut self, name: &str, var_type: VariableType) -> Result<(), Error> {
        if let Some(e) = self.vars.get(name) {
            if e.var_type != var_type {
                return Err(Error::ConflictingVariableType(
                    String::from(name),
                    e.var_type.to_string(),
                    var_type.to_string(),
                ));
            }
        } else {
            self.vars.insert(
                String::from(name),
                Variable {
                    name: String::from(name),
                    var_type,
                },
            );
        }
        Ok(())
    }
    pub fn validate_params(&self, params: &mut Parameters) -> Result<(), Error> {
        for var in &self.vars {
            let var_name = var.0.to_string();

            if let Some(p) = params.params.remove(&var_name) {
                match var.1.var_type {
                    VariableType::Boolean(nullable) => {
                        match p {
                            ParamValue::Boolean(_) => {}
                            ParamValue::Null => {
                                if !nullable {
                                    return Err(Error::NotNullable(var.0.to_string()));
                                }
                            }
                            _ => {
                                return Err(Error::ConflictingParameterType(
                                    var.0.to_string(),
                                    "Boolean".to_string(),
                                    format!("{:#?}", p),
                                ));
                            }
                        }
                        params.params.insert(var_name, p);
                    }
                    VariableType::String(nullable) => {
                        match p {
                            ParamValue::String(_) => {}
                            ParamValue::Null => {
                                if !nullable {
                                    return Err(Error::NotNullable(var.0.to_string()));
                                }
                            }
                            _ => {
                                return Err(Error::ConflictingParameterType(
                                    var.0.to_string(),
                                    "String".to_string(),
                                    format!("{:#?}", p),
                                ));
                            }
                        }
                        params.params.insert(var_name, p);
                    }

                    VariableType::Integer(nullable) => {
                        match p {
                            ParamValue::Integer(_) => {}
                            ParamValue::Null => {
                                if !nullable {
                                    return Err(Error::NotNullable(var.0.to_string()));
                                }
                            }
                            _ => {
                                return Err(Error::ConflictingParameterType(
                                    var.0.to_string(),
                                    "Integer".to_string(),
                                    format!("{:#?}", p),
                                ));
                            }
                        }

                        params.params.insert(var_name, p);
                    }

                    VariableType::Float(nullable) => {
                        match p {
                            ParamValue::Float(_) => {}
                            ParamValue::Integer(_) => {}
                            ParamValue::Null => {
                                if !nullable {
                                    return Err(Error::NotNullable(var.0.to_string()));
                                }
                            }
                            _ => {
                                return Err(Error::ConflictingParameterType(
                                    var.0.to_string(),
                                    "Float".to_string(),
                                    format!("{:#?}", p),
                                ));
                            }
                        }
                        params.params.insert(var_name, p);
                    }

                    VariableType::Base64(nullable) => {
                        match &p {
                            ParamValue::String(e) => {
                                let decode = base64_decode(e.as_bytes());
                                if decode.is_err() {
                                    return Err(Error::InvalidBase64(e.clone()));
                                }
                            }
                            ParamValue::Null => {
                                if !nullable {
                                    return Err(Error::NotNullable(var.0.to_string()));
                                }
                            }
                            _ => {
                                return Err(Error::ConflictingParameterType(
                                    var.0.to_string(),
                                    "Base64".to_string(),
                                    format!("{:#?}", p),
                                ));
                            }
                        }
                        params.params.insert(var_name, p);
                    }

                    VariableType::Binary(nullable) => {
                        let bin_param = match &p {
                            ParamValue::Binary(e) => {
                                let decode = base64_decode(e.as_bytes());
                                if decode.is_err() {
                                    return Err(Error::InvalidBase64(e.clone()));
                                }
                                p
                            }
                            ParamValue::String(e) => {
                                let decode = base64_decode(e.as_bytes());
                                if decode.is_err() {
                                    return Err(Error::InvalidBase64(e.clone()));
                                }
                                ParamValue::Binary(e.clone())
                            }

                            ParamValue::Null => {
                                if !nullable {
                                    return Err(Error::NotNullable(var.0.to_string()));
                                }
                                p
                            }
                            _ => {
                                return Err(Error::ConflictingParameterType(
                                    var.0.to_string(),
                                    "Binary".to_string(),
                                    format!("{:#?}", p),
                                ));
                            }
                        };
                        params.params.insert(var_name, bin_param);
                    }

                    VariableType::Json(nullable) => {
                        match &p {
                            ParamValue::String(s) => {
                                let v: std::result::Result<serde_json::Value, serde_json::Error> =
                                    serde_json::from_str(s);
                                if v.is_err() {
                                    return Err(Error::InvalidJson(s.clone()));
                                }
                            }
                            ParamValue::Null => {
                                if !nullable {
                                    return Err(Error::NotNullable(var.0.to_string()));
                                }
                            }
                            _ => {
                                return Err(Error::ConflictingParameterType(
                                    var.0.to_string(),
                                    "String".to_string(),
                                    format!("{:#?}", p),
                                ));
                            }
                        }
                        params.params.insert(var_name, p);
                    }

                    VariableType::Invalid => {
                        params.params.insert(var_name, p);
                    }
                }
            } else {
                return Err(Error::MissingParameter(String::from(var.0)));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Parameters {
    pub params: HashMap<String, ParamValue>,
}
pub trait ParametersAdd<T> {
    fn add(&mut self, key: &str, val: T) -> Result<(), Error>;
}
impl Default for Parameters {
    fn default() -> Self {
        Parameters::new()
    }
}

impl ParametersAdd<bool> for Parameters {
    fn add(&mut self, key: &str, value: bool) -> Result<(), Error> {
        self.exists_err(key)?;
        self.params
            .insert(String::from(key), ParamValue::Boolean(value));
        Ok(())
    }
}

impl ParametersAdd<i64> for Parameters {
    fn add(&mut self, key: &str, value: i64) -> Result<(), Error> {
        self.exists_err(key)?;
        self.params
            .insert(String::from(key), ParamValue::Integer(value));
        Ok(())
    }
}

impl ParametersAdd<f64> for Parameters {
    fn add(&mut self, key: &str, value: f64) -> Result<(), Error> {
        self.exists_err(key)?;
        self.params
            .insert(String::from(key), ParamValue::Float(value));
        Ok(())
    }
}

impl ParametersAdd<String> for Parameters {
    fn add(&mut self, key: &str, value: String) -> Result<(), Error> {
        self.exists_err(key)?;
        self.params
            .insert(String::from(key), ParamValue::String(value));
        Ok(())
    }
}

impl Parameters {
    pub fn new() -> Self {
        Self {
            params: HashMap::new(),
        }
    }

    fn exists_err(&mut self, key: &str) -> Result<(), Error> {
        if self.params.contains_key(key) {
            return Err(Error::DuplicatedParameters(format!(
                "parameter '{}' allready exist ",
                key
            )));
        }
        Ok(())
    }

    pub fn add_null(&mut self, key: &str) -> Result<(), Error> {
        self.exists_err(key)?;
        self.params.insert(String::from(key), ParamValue::Null);
        Ok(())
    }

    pub fn parse(p: &str) -> Result<Self, Error> {
        let mut parameters = Parameters {
            params: HashMap::new(),
        };

        let mut parse = match PestParser::parse(Rule::parameters, p) {
            Err(e) => {
                let message = format!("{}", e);
                return Err(Error::Parser(message));
            }
            Ok(f) => f,
        };

        let param_pairs = parse.next().unwrap().into_inner();
        for param_pair in param_pairs {
            match param_pair.as_rule() {
                Rule::field => {
                    let mut pairs = param_pair.into_inner();
                    let name = pairs.next().unwrap().as_str();
                    let value_pair = pairs.next().unwrap().into_inner().next().unwrap();
                    let value = value_pair.as_str();
                    match value_pair.as_rule() {
                        Rule::string => {
                            parameters.add(name, value.to_string())?;
                        }
                        Rule::null => {
                            parameters.add_null(name)?;
                        }
                        Rule::boolean => {
                            let val: bool = value.parse()?;
                            parameters.add(name, val)?;
                        }
                        Rule::integer => {
                            let val: i64 = value.parse()?;
                            parameters.add(name, val)?;
                        }
                        Rule::float => {
                            let val: f64 = value.parse()?;
                            parameters.add(name, val)?;
                        }
                        _ => unreachable!(),
                    }
                }
                Rule::EOI => {}
                _ => unreachable!(),
            }
        }

        Ok(parameters)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn parse_valid_parameters() {
        let _ = Parameters::parse(
            r#"
            //comment
        {
            "a_float" : 1.2 ,
            "a_string":"hello .world" ,
            "a_bool" : true ,
            "a_null" : null ,
            "an_integer" : -123,
        }
        "#,
        )
        .unwrap();

        // println!("{:#?}", p);
    }

    #[test]
    fn variables_duplicate() {
        let mut vars = Variables::new();
        vars.add("bool", VariableType::Boolean(false)).unwrap();

        vars.add("bool", VariableType::Boolean(false))
            .expect("duplicate name with identical VariableType results in a noop");

        vars.add("bool", VariableType::Boolean(true))
            .expect_err("duplicate name with a different VariableType return an error ");
    }

    #[test]
    fn params_duplicate() {
        let mut param = Parameters::new();
        param.add("name", true).unwrap();
        param
            .add("name", true)
            .expect_err("It is forbidden to insert duplicate names");
    }

    #[test]
    fn variables_validate_bool_type() {
        let name = "bool";

        let mut vars = Variables::new();
        vars.add(name, VariableType::Boolean(false)).unwrap();
        let mut param = Parameters::new();
        vars.validate_params(&mut param)
            .expect_err("param has a missing value");

        param = Parameters::new();
        param.add(name, 1).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param has the wrong type");

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param cannot be null");

        vars = Variables::new();
        vars.add(name, VariableType::Boolean(true)).unwrap();

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param).expect("param can be null");

        param = Parameters::new();
        param.add(name, true).unwrap();
        vars.validate_params(&mut param)
            .expect("param has the right type");
    }

    #[test]
    fn variables_validate_float_type() {
        let name = "float";

        let mut vars = Variables::new();
        vars.add(name, VariableType::Float(false)).unwrap();
        let mut param = Parameters::new();
        vars.validate_params(&mut param)
            .expect_err("param has a missing value");

        param = Parameters::new();
        param.add(name, true).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param has the wrong type");

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param cannot be null");

        vars = Variables::new();
        vars.add(name, VariableType::Float(true)).unwrap();

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param).expect("param can be null");

        param = Parameters::new();
        param.add(name, 1.23).unwrap();
        vars.validate_params(&mut param)
            .expect("param has the right type");

        param = Parameters::new();
        param.add(name, 123).unwrap();
        vars.validate_params(&mut param)
            .expect("Integer params will be casted to float");
    }

    #[test]
    fn variables_validate_integer_type() {
        let name = "integer";

        let mut vars = Variables::new();
        vars.add(name, VariableType::Integer(false)).unwrap();
        let mut param = Parameters::new();
        vars.validate_params(&mut param)
            .expect_err("param has a missing value");

        param = Parameters::new();
        param.add(name, true).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param has the wrong type");

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param cannot be null");

        vars = Variables::new();
        vars.add(name, VariableType::Integer(true)).unwrap();

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param).expect("param can be null");

        param = Parameters::new();
        param.add(name, 1.23).unwrap();
        vars.validate_params(&mut param)
            .expect_err("Floats ARE NOT cast to integer");

        param = Parameters::new();
        param.add(name, 123).unwrap();
        vars.validate_params(&mut param)
            .expect("param has the right type");
    }

    #[test]
    fn variables_validate_string_type() {
        let name = "string";

        let mut vars = Variables::new();
        vars.add(name, VariableType::String(false)).unwrap();
        let mut param = Parameters::new();
        vars.validate_params(&mut param)
            .expect_err("param has a missing value");

        param = Parameters::new();
        param.add(name, true).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param has the wrong type");

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param cannot be null");

        vars = Variables::new();
        vars.add(name, VariableType::String(true)).unwrap();

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param).expect("param can be null");

        param = Parameters::new();
        param.add(name, "hello".to_string()).unwrap();
        vars.validate_params(&mut param)
            .expect("param has the right type");
    }

    #[test]
    fn variables_validate_base64_type() {
        let name = "UID";

        let mut vars = Variables::new();
        vars.add(name, VariableType::Base64(false)).unwrap();
        let mut param = Parameters::new();
        vars.validate_params(&mut param)
            .expect_err("param has a missing value");

        param = Parameters::new();
        param.add(name, true).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param has the wrong type");

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param cannot be null");

        vars = Variables::new();
        vars.add(name, VariableType::Base64(true)).unwrap();

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param).expect("param can be null");

        param = Parameters::new();
        param.add(name, "0123456789ABCDEF".to_string()).unwrap();
        vars.validate_params(&mut param)
            .expect("param has the right type");

        param = Parameters::new();
        param.add(name, "0123456789abcdef".to_string()).unwrap();
        vars.validate_params(&mut param)
            .expect("param has the right type");

        param = Parameters::new();
        param.add(name, "+^%".to_string()).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param is not an base64 string");
    }

    #[test]
    fn variables_validate_json_type() {
        let name = "JSON";

        let mut vars = Variables::new();
        vars.add(name, VariableType::Json(false)).unwrap();
        let mut param = Parameters::new();
        vars.validate_params(&mut param)
            .expect_err("param has a missing value");

        param = Parameters::new();
        param.add(name, true).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param has the wrong type");

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param)
            .expect_err("param cannot be null");

        vars = Variables::new();
        vars.add(name, VariableType::Json(true)).unwrap();

        param = Parameters::new();
        param.add_null(name).unwrap();
        vars.validate_params(&mut param).expect("param can be null");

        param = Parameters::new();
        param
            .add(name, r#"  "param":"value"  "#.to_string())
            .unwrap();
        vars.validate_params(&mut param)
            .expect_err("not a valid JSON");

        param = Parameters::new();
        param
            .add(name, r#"{  "param":"value"  }"#.to_string())
            .unwrap();
        vars.validate_params(&mut param).expect("valid json");

        param = Parameters::new();
        param.add(name, "[0,1,2]".to_string()).unwrap();
        vars.validate_params(&mut param).expect("valid json");
    }
}
