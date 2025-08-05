use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(FieldNames)]
pub fn derive_field_names(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let fields = match input.data {
        syn::Data::Struct(s) => s
            .fields
            .into_iter()
            .map(|f| {
                let field_name = f.ident.expect("Expected named fields");
                // For now, just convert to camelCase since that's what serde does with rename_all = "camelCase"
                to_camel_case(&field_name.to_string())
            })
            .collect::<Vec<_>>(),
        _ => panic!("FieldNames only supports structs with named fields"),
    };

    let field_strs: Vec<String> = fields.iter().map(|f| f.to_string()).collect();

    let expanded = quote! {
        impl #struct_name {
            pub fn field_names() -> &'static [&'static str] {
                &[#(#field_strs),*]
            }
        }
    };

    expanded.into()
}

fn to_camel_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = false;
    
    for (i, ch) in s.chars().enumerate() {
        if ch == '_' {
            capitalize_next = true;
        } else if i == 0 {
            result.push(ch.to_lowercase().next().unwrap());
        } else if capitalize_next {
            result.push(ch.to_uppercase().next().unwrap());
            capitalize_next = false;
        } else {
            result.push(ch);
        }
    }
    
    result
} 