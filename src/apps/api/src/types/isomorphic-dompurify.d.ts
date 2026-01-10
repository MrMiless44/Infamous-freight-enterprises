declare module "isomorphic-dompurify" {
  import { DOMPurifyI } from "dompurify";
  function createDOMPurify(): DOMPurifyI;
  export default createDOMPurify;
}
