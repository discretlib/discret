use std::collections::HashMap;

use crate::base64_decode;

use super::{Error, Value, VariableType};

use pest::Parser;
use pest_derive::Parser;
use rusqlite::ToSql;

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

    pub fn add(&mut self, name: String, var_type: VariableType) -> Result<(), Error> {
        if let Some(e) = self.vars.get(&name) {
            if e.var_type != var_type {
                return Err(Error::ConflictingVariableType(
                    name,
                    e.var_type.to_string(),
                    var_type.to_string(),
                ));
            }
        } else {
            self.vars.insert(name.clone(), Variable { name, var_type });
        }
        Ok(())
    }
    pub fn validate_params(&self, params: &Parameters) -> Result<(), Error> {
        for var in &self.vars {
            if let Some(p) = params.params.get(var.0) {
                match var.1.var_type {
                    VariableType::Boolean(nullable) => match p {
                        Value::Boolean(_) => {}
                        Value::Null => {
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
                    },
                    VariableType::String(nullable) => match p {
                        Value::String(_) => {}
                        Value::Null => {
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
                    },
                    VariableType::Integer(nullable) => match p {
                        Value::Integer(_) => {}
                        Value::Null => {
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
                    },

                    VariableType::Float(nullable) => match p {
                        Value::Float(_) => {}
                        Value::Integer(_) => {}
                        Value::Null => {
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
                    },

                    VariableType::Base64(nullable) => match p {
                        Value::String(e) => {
                            let decode = base64_decode(e.as_bytes());
                            if decode.is_err() {
                                return Err(Error::InvalidBase64(e.clone()));
                            }
                        }
                        Value::Null => {
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
                    },
                }
            } else {
                return Err(Error::MissingParameter(format!(
                    "Parameter: '{}' is missing",
                    var.0
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Parameters {
    pub params: HashMap<String, Value>,
}
impl Default for Parameters {
    fn default() -> Self {
        Parameters::new()
    }
}
impl Parameters {
    pub fn new() -> Self {
        Self {
            params: HashMap::new(),
        }
    }

    pub fn add(&mut self, name: String, value: Value) -> Result<(), Error> {
        if self.params.contains_key(&name) {
            return Err(Error::DuplicatedParameters(format!(
                "parameter '{}' is duplicated ",
                &name
            )));
        }
        self.params.insert(name, value);
        Ok(())
    }

    pub fn parse(p: &str) -> Result<Self, Error> {
        let mut parameters = Parameters {
            params: HashMap::new(),
        };

        let mut parse = match PestParser::parse(Rule::parameters, p) {
            Err(e) => {
                let message = format!("{}", e);
                return Err(Error::ParserError(message));
            }
            Ok(f) => f,
        };

        let param_pairs = parse.next().unwrap().into_inner();
        for param_pair in param_pairs {
            match param_pair.as_rule() {
                Rule::field => {
                    let mut pairs = param_pair.into_inner();
                    let name = pairs.next().unwrap().as_str().to_string();
                    let value_pair = pairs.next().unwrap().into_inner().next().unwrap();
                    let value = value_pair.as_str();
                    match value_pair.as_rule() {
                        Rule::string => {
                            let val = Value::String(value.to_string());
                            parameters.add(name, val)?;
                        }
                        Rule::null => {
                            parameters.add(name, Value::Null)?;
                        }
                        Rule::boolean => {
                            let val = Value::Boolean(value.parse()?);
                            parameters.add(name, val)?;
                        }
                        Rule::integer => {
                            let val = Value::Integer(value.parse()?);
                            parameters.add(name, val)?;
                        }
                        Rule::float => {
                            let val = Value::Float(value.parse()?);
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

pub struct SQLVariables {
    vars: Vec<String>,
}
impl Default for SQLVariables {
    fn default() -> Self {
        SQLVariables::new()
    }
}
impl SQLVariables {
    pub fn new() -> Self {
        Self { vars: Vec::new() }
    }

    pub fn build_query_params(
        &self,
        params: Parameters,
    ) -> Result<Vec<Box<dyn ToSql + Sync + Send>>, Error> {
        let mut v: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
        for var in &self.vars {
            let para = params.params.get(var);
            if let Some(val) = para {
                match val {
                    Value::Boolean(e) => {
                        v.push(Box::new(*e));
                    }
                    Value::Float(e) => {
                        v.push(Box::new(*e));
                    }
                    Value::Integer(e) => {
                        v.push(Box::new(*e));
                    }
                    Value::Null => {
                        let null: Option<String> = None;
                        v.push(Box::new(null));
                    }
                    Value::String(e) => {
                        v.push(Box::new(e.clone()));
                    }
                }
            } else {
                return Err(Error::MissingParameter(format!(
                    "Missing parameter: '{}', Cannot build SQL query parameters",
                    var
                )));
            }
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn parse_valid_parameters() {
        let _ = Parameters::parse(
            r#"
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
        vars.add("bool".to_string(), VariableType::Boolean(false))
            .unwrap();

        vars.add("bool".to_string(), VariableType::Boolean(false))
            .expect("duplicate name with identical VariableType results in a noop");

        vars.add("bool".to_string(), VariableType::Boolean(true))
            .expect_err("duplicate name with a different VariableType return an error ");
    }

    #[test]
    fn params_duplicate() {
        let mut param = Parameters::new();
        param.add("name".to_string(), Value::Boolean(true)).unwrap();
        param
            .add("name".to_string(), Value::Boolean(true))
            .expect_err("It is forbidden to insert duplicate names");
    }

    #[test]
    fn variables_validate_bool_type() {
        let name = "bool";

        let mut vars = Variables::new();
        vars.add(name.to_string(), VariableType::Boolean(false))
            .unwrap();
        let mut param = Parameters::new();
        vars.validate_params(&param)
            .expect_err("param has a missing value");

        param = Parameters::new();
        param.add(name.to_string(), Value::Integer(1)).unwrap();
        vars.validate_params(&param)
            .expect_err("param has the wrong type");

        param = Parameters::new();
        param.add(name.to_string(), Value::Null).unwrap();
        vars.validate_params(&param)
            .expect_err("param cannot be null");

        vars = Variables::new();
        vars.add(name.to_string(), VariableType::Boolean(true))
            .unwrap();

        param = Parameters::new();
        param.add(name.to_string(), Value::Null).unwrap();
        vars.validate_params(&param).expect("param can be null");

        param = Parameters::new();
        param.add(name.to_string(), Value::Boolean(true)).unwrap();
        vars.validate_params(&param)
            .expect("param has the right type");
    }

    #[test]
    fn variables_validate_float_type() {
        let name = "float";

        let mut vars = Variables::new();
        vars.add(name.to_string(), VariableType::Float(false))
            .unwrap();
        let mut param = Parameters::new();
        vars.validate_params(&param)
            .expect_err("param has a missing value");

        param = Parameters::new();
        param.add(name.to_string(), Value::Boolean(true)).unwrap();
        vars.validate_params(&param)
            .expect_err("param has the wrong type");

        param = Parameters::new();
        param.add(name.to_string(), Value::Null).unwrap();
        vars.validate_params(&param)
            .expect_err("param cannot be null");

        vars = Variables::new();
        vars.add(name.to_string(), VariableType::Float(true))
            .unwrap();

        param = Parameters::new();
        param.add(name.to_string(), Value::Null).unwrap();
        vars.validate_params(&param).expect("param can be null");

        param = Parameters::new();
        param.add(name.to_string(), Value::Float(1.23)).unwrap();
        vars.validate_params(&param)
            .expect("param has the right type");

        param = Parameters::new();
        param.add(name.to_string(), Value::Integer(123)).unwrap();
        vars.validate_params(&param)
            .expect("Integer params will be casted to float");
    }

    #[test]
    fn variables_validate_integer_type() {
        let name = "integer";

        let mut vars = Variables::new();
        vars.add(name.to_string(), VariableType::Integer(false))
            .unwrap();
        let mut param = Parameters::new();
        vars.validate_params(&param)
            .expect_err("param has a missing value");

        param = Parameters::new();
        param.add(name.to_string(), Value::Boolean(true)).unwrap();
        vars.validate_params(&param)
            .expect_err("param has the wrong type");

        param = Parameters::new();
        param.add(name.to_string(), Value::Null).unwrap();
        vars.validate_params(&param)
            .expect_err("param cannot be null");

        vars = Variables::new();
        vars.add(name.to_string(), VariableType::Integer(true))
            .unwrap();

        param = Parameters::new();
        param.add(name.to_string(), Value::Null).unwrap();
        vars.validate_params(&param).expect("param can be null");

        param = Parameters::new();
        param.add(name.to_string(), Value::Float(1.23)).unwrap();
        vars.validate_params(&param)
            .expect_err("Floats ARE NOT cast to integer");

        param = Parameters::new();
        param.add(name.to_string(), Value::Integer(123)).unwrap();
        vars.validate_params(&param)
            .expect("param has the right type");
    }

    #[test]
    fn variables_validate_string_type() {
        let name = "string";

        let mut vars = Variables::new();
        vars.add(name.to_string(), VariableType::String(false))
            .unwrap();
        let mut param = Parameters::new();
        vars.validate_params(&param)
            .expect_err("param has a missing value");

        param = Parameters::new();
        param.add(name.to_string(), Value::Boolean(true)).unwrap();
        vars.validate_params(&param)
            .expect_err("param has the wrong type");

        param = Parameters::new();
        param.add(name.to_string(), Value::Null).unwrap();
        vars.validate_params(&param)
            .expect_err("param cannot be null");

        vars = Variables::new();
        vars.add(name.to_string(), VariableType::String(true))
            .unwrap();

        param = Parameters::new();
        param.add(name.to_string(), Value::Null).unwrap();
        vars.validate_params(&param).expect("param can be null");

        param = Parameters::new();
        param
            .add(name.to_string(), Value::String("hello".to_string()))
            .unwrap();
        vars.validate_params(&param)
            .expect("param has the right type");
    }

    #[test]
    fn variables_validate_uid_type() {
        let name = "UID";

        let mut vars = Variables::new();
        vars.add(name.to_string(), VariableType::Base64(false))
            .unwrap();
        let mut param = Parameters::new();
        vars.validate_params(&param)
            .expect_err("param has a missing value");

        param = Parameters::new();
        param.add(name.to_string(), Value::Boolean(true)).unwrap();
        vars.validate_params(&param)
            .expect_err("param has the wrong type");

        param = Parameters::new();
        param.add(name.to_string(), Value::Null).unwrap();
        vars.validate_params(&param)
            .expect_err("param cannot be null");

        vars = Variables::new();
        vars.add(name.to_string(), VariableType::Base64(true))
            .unwrap();

        param = Parameters::new();
        param.add(name.to_string(), Value::Null).unwrap();
        vars.validate_params(&param).expect("param can be null");

        param = Parameters::new();
        param
            .add(
                name.to_string(),
                Value::String("0123456789ABCDEF".to_string()),
            )
            .unwrap();
        vars.validate_params(&param)
            .expect("param has the right type");

        param = Parameters::new();
        param
            .add(
                name.to_string(),
                Value::String("0123456789abcdef".to_string()),
            )
            .unwrap();
        vars.validate_params(&param)
            .expect("param has the right type");

        param = Parameters::new();
        param
            .add(name.to_string(), Value::String("+^%".to_string()))
            .unwrap();
        vars.validate_params(&param)
            .expect_err("param is not an base64 string");
    }
}
