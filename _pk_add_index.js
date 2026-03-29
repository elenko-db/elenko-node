const fs = require("fs");
const p = "c:/Users/Juergen/Software/node.js/Elenko/server.js";
let s = fs.readFileSync(p, "utf8");
if (s.includes("records-by-primarykey")) {
  console.log("index exists");
  process.exit(0);
}
const block = `
  // Index for business primaryKey (global uniqueness / lookup)
  try {
    await db.createIndex({
      index: { fields: ["type", "primaryKey"] },
      name: "records-by-primarykey",
    });
  } catch (e) {
    // Index may already exist
  }
`;
const needle = `  } catch (e) {
    // Index may already exist
  }

  // View to count entries per profile (for pagination "Page x of N")`;
if (!s.includes(needle)) {
  console.error("needle not found");
  process.exit(1);
}
s = s.replace(needle, `  } catch (e) {
    // Index may already exist
  }${block}

  // View to count entries per profile (for pagination "Page x of N")`);
fs.writeFileSync(p, s);
console.log("index added");
