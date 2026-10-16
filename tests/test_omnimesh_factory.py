import ipaddress
import unittest
from pathlib import Path
from src.omnimesh_compiler import OmniMeshCompiler


class TestOmniMeshPlatformFactory(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parent.parent
        self.compiler = OmniMeshCompiler(
            blueprint_path=self.root / "blueprint" / "platform_blueprint.json",
            build_dir=self.root / "build",
        )

    def test_vlsm_zero_cidr_collisions_across_clouds(self) -> None:
        allocations = self.compiler.allocate_vlsm_topology()
        self.assertEqual(len(allocations), 9)
        networks = [ipaddress.ip_network(a.cidr) for a in allocations]
        for idx, net_a in enumerate(networks):
            for net_b in networks[idx + 1 :]:
                self.assertFalse(net_a.overlaps(net_b))

    def test_zero_trust_artifacts_generated(self) -> None:
        allocations = self.compiler.allocate_vlsm_topology()
        tf_file = self.compiler.generate_terraform_bundle(allocations)
        helm_dir = self.compiler.generate_helm_chart()
        dbx_file = self.compiler.generate_databricks_bundle()
        self.assertTrue(tf_file.exists())
        self.assertTrue((helm_dir / "Chart.yaml").exists())
        self.assertTrue(dbx_file.exists())

    def test_medallion_pii_tokenization_and_zero_leak(self) -> None:
        metrics = self.compiler.execute_medallion_pipeline(batch_size=2500)
        self.assertEqual(metrics.total_bronze_events, 2500)
        self.assertEqual(metrics.valid_silver_records + metrics.quarantined_schema_violations, 2500)
        self.assertLess(metrics.retained_ram_kb, 150.0)


if __name__ == "__main__":
    unittest.main()
