"""Main CLI entry point for LogLens."""

from typing import Optional
import typer
from pathlib import Path

app = typer.Typer(
    name="loglens",
    help="LogLens - Log Analysis Tool for analyzing and detecting patterns in log files",
    add_completion=True,
)


@app.command()
def analyze(
    log_file: Path = typer.Argument(
        ..., 
        help="Path to the log file to analyze",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for the analysis report",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
) -> None:
    """Analyze a log file for patterns and generate a report."""
    from .services.ingestion import LogFileIngester, IngestionError
    
    if verbose:
        typer.echo(f"Analyzing log file: {log_file}")
        if output:
            typer.echo(f"Output will be saved to: {output}")
    
    typer.echo(f"🔍 LogLens Analysis starting for: {log_file.name}")
    
    # Step 1: Ingest log file
    try:
        ingester = LogFileIngester(show_progress=True)
        
        if verbose:
            typer.echo("📄 Starting file ingestion...")
        
        # For now, we'll read all lines into memory for analysis
        # Future stories will add streaming processing for larger files
        lines, result = ingester.ingest_file_to_list(log_file)
        
        # Display ingestion results
        typer.echo(f"✅ File ingestion complete:")
        typer.echo(f"   📊 Lines processed: {result.lines_processed:,}")
        typer.echo(f"   📏 File size: {result.metadata.file_size / 1024:.1f} KB")
        typer.echo(f"   🕒 Duration: {result.duration_seconds:.2f} seconds" if result.duration_seconds else "   🕒 Duration: < 0.01 seconds")
        typer.echo(f"   🔤 Encoding: {result.metadata.encoding}")
        
        if verbose and len(lines) > 0:
            typer.echo("\n📝 Sample log lines:")
            for i, line in enumerate(lines[:3]):  # Show first 3 lines
                typer.echo(f"   {line.line_number}: {line.content[:100]}{'...' if len(line.content) > 100 else ''}")
            if len(lines) > 3:
                typer.echo(f"   ... and {len(lines) - 3:,} more lines")
        
        # Step 2: Parse log lines using Apache parser
        if verbose:
            typer.echo("\n🔍 Starting log parsing...")
        
        from .services.parsing import ApacheParser
        
        parser = ApacheParser()
        parsed_results = list(parser.parse_batch(iter(lines)))
        stats = parser.get_statistics()
        
        # Display parsing results
        typer.echo(f"\n✅ Log parsing complete:")
        typer.echo(f"   📊 Lines parsed: {stats.total_lines:,}")
        typer.echo(f"   ✅ Successful parses: {stats.successful_parses:,}")
        typer.echo(f"   ❌ Parse errors: {stats.errors:,}")
        typer.echo(f"   📈 Success rate: {stats.success_rate:.1f}%")
        typer.echo(f"   🕒 Processing time: {stats.processing_time:.3f} seconds")
        
        if verbose and stats.errors > 0:
            typer.echo("\n❌ Parse error details:")
            for error in stats.error_details[:5]:  # Show first 5 errors
                typer.echo(f"   Line {error['line_number']}: {error['error']}")
                typer.echo(f"      Raw: {error['raw_line'][:80]}{'...' if len(error['raw_line']) > 80 else ''}")
            if len(stats.error_details) > 5:
                typer.echo(f"   ... and {len(stats.error_details) - 5} more errors")
        
        if verbose and stats.successful_parses > 0:
            typer.echo("\n📝 Sample parsed entries:")
            success_count = 0
            for result in parsed_results:
                if result.success and success_count < 3:
                    entry = result.entry
                    typer.echo(f"   IP: {entry.ip_address} | Time: {entry.timestamp} | Status: {entry.status_code}")
                    typer.echo(f"      Request: {entry.request_line[:60]}{'...' if len(entry.request_line) > 60 else ''}")
                    success_count += 1
                if success_count >= 3:
                    break
        
        # Step 3: Run detection analysis
        if verbose:
            typer.echo("\n🔍 Starting detection analysis...")
        
        from .services.detection import DetectionEngine
        
        # Extract successfully parsed entries
        parsed_entries = [result.entry for result in parsed_results if result.success]
        
        if len(parsed_entries) > 0:
            detection_engine = DetectionEngine()
            detection_result = detection_engine.analyze_entries(parsed_entries)
            
            # Display detection results
            typer.echo(f"\n✅ Detection analysis complete:")
            typer.echo(f"   📊 Entries analyzed: {detection_result.total_entries_analyzed:,}")
            typer.echo(f"   🚨 Total findings: {detection_result.total_findings:,}")
            typer.echo(f"   🔴 High risk: {detection_result.high_risk_findings}")
            typer.echo(f"   🟡 Medium risk: {detection_result.medium_risk_findings}")
            typer.echo(f"   🟢 Low risk: {detection_result.low_risk_findings}")
            typer.echo(f"   ℹ️  Info level: {detection_result.info_findings}")
            typer.echo(f"   🕒 Processing time: {detection_result.processing_time_seconds:.3f} seconds" if detection_result.processing_time_seconds else "   🕒 Processing time: < 0.01 seconds")
            
            # Display enhanced frequency detection statistics if verbose
            if verbose:
                detector_stats = detection_engine.get_combined_statistics()
                detector_summary = detection_engine.get_detector_summary()
                
                typer.echo("\n📊 Advanced Detection Statistics:")
                
                # Show detector status
                enabled_detectors = [name for name, status in detector_summary.items() if status == 'enabled']
                typer.echo(f"   🔧 Active detectors: {', '.join(enabled_detectors)}")
                
                # Show detailed stats for each detector
                for detector_name, stats in detector_stats.items():
                    if stats.total_findings > 0:
                        detector_display_name = detector_name.replace('_', ' ').title()
                        typer.echo(f"   📈 {detector_display_name}:")
                        typer.echo(f"      Findings: {stats.total_findings} | High: {stats.high_risk_count} | Med: {stats.medium_risk_count} | Low: {stats.low_risk_count}")
                        if stats.processing_errors > 0:
                            typer.echo(f"      ⚠️  Errors: {stats.processing_errors}")
                
                # Show frequency pattern types found
                pattern_types = {}
                for finding in detection_result.findings:
                    if finding.enrichment_data and 'pattern_type' in finding.enrichment_data:
                        pattern_type = finding.enrichment_data['pattern_type']
                        pattern_types[pattern_type] = pattern_types.get(pattern_type, 0) + 1
                
                if pattern_types:
                    typer.echo("   🎯 Pattern Types Detected:")
                    for pattern_type, count in sorted(pattern_types.items(), key=lambda x: x[1], reverse=True):
                        pattern_display = pattern_type.replace('_', ' ').title()
                        typer.echo(f"      {pattern_display}: {count}")
            
            
            # Step 4: Enrich findings with IP reputation data
            if detection_result.total_findings > 0:
                if verbose:
                    typer.echo("\n🌐 Starting IP reputation enrichment...")
                
                try:
                    import asyncio
                    from .services.enrichment import create_enrichment_engine
                    
                    enrichment_engine = create_enrichment_engine()
                    
                    if len(enrichment_engine.providers) > 0:
                        # Run enrichment asynchronously
                        enriched_findings = asyncio.run(
                            enrichment_engine.enrich_findings(detection_result.findings)
                        )
                        enrichment_stats = enrichment_engine.get_statistics()
                        
                        # Display enrichment results
                        typer.echo(f"\n✅ IP reputation enrichment complete:")
                        typer.echo(f"   🌐 Unique IPs queried: {enrichment_stats.ips_queried}")
                        typer.echo(f"   ✅ Successful lookups: {enrichment_stats.successful_lookups}")
                        typer.echo(f"   ❌ API errors: {enrichment_stats.api_errors}")
                        typer.echo(f"   💾 Cache hits: {enrichment_stats.cache_hits}")
                        typer.echo(f"   🛡️  Providers used: {', '.join(enrichment_stats.providers_used)}")
                        typer.echo(f"   📈 Findings enriched: {enrichment_stats.total_findings_enriched}")
                        typer.echo(f"   📊 Success rate: {enrichment_stats.success_rate:.1f}%")
                        typer.echo(f"   🕒 Processing time: {enrichment_stats.processing_time:.3f} seconds")
                        
                        if verbose and enrichment_stats.api_errors > 0 and enrichment_stats.error_details:
                            typer.echo("\n⚠️  Enrichment warnings:")
                            for error in enrichment_stats.error_details[:3]:  # Show first 3 errors
                                typer.echo(f"   {error}")
                            if len(enrichment_stats.error_details) > 3:
                                typer.echo(f"   ... and {len(enrichment_stats.error_details) - 3} more warnings")
                        
                        # Update detection result with enriched findings
                        detection_result.findings = enriched_findings
                        
                    else:
                        typer.echo("\n⚠️  No enrichment providers configured. Skipping IP reputation enrichment.")
                        typer.echo("   💡 Configure API keys in environment variables or ~/.loglens/config.yml")
                        
                except Exception as e:
                    typer.echo(f"\n⚠️  Enrichment failed: {str(e)}")
                    if verbose:
                        import traceback
                        typer.echo(traceback.format_exc(), err=True)
                    typer.echo("   Continuing with non-enriched findings...")
            
            # Step 5: Generate and display security analysis report
            try:
                from .services.reporting import ReportingService, OutputConfig, ReportFormat
                
                # Configure reporting based on CLI options
                config = OutputConfig(
                    format=ReportFormat.FILE if output else ReportFormat.CONSOLE,
                    file_path=output,
                    max_findings=5,  # Default view: top 5 findings
                    max_findings_verbose=10,  # Verbose view: top 10 findings
                    include_executive_summary=True,
                    include_recommendations=True,
                    terminal_width=79
                )
                
                reporting_service = ReportingService(config)
                
                # Generate the complete security analysis report
                report_content = reporting_service.generate_report(detection_result, verbose=verbose)
                
                if output:
                    # Save report to file
                    reporting_service.save_report(report_content, output)
                    typer.echo(f"\n📄 Security analysis report saved to: {output}")
                    
                    # Also display a summary to console
                    typer.echo("\n" + "=" * 79)
                    typer.echo("                           REPORT SUMMARY")
                    typer.echo("=" * 79)
                    if detection_result.total_findings > 0:
                        typer.echo(f"🚨 {detection_result.total_findings} security findings detected")
                        typer.echo(f"🔴 High risk: {detection_result.high_risk_findings}")
                        typer.echo(f"🟡 Medium risk: {detection_result.medium_risk_findings}")
                        typer.echo(f"🟢 Low risk: {detection_result.low_risk_findings}")
                        typer.echo(f"ℹ️  Info: {detection_result.info_findings}")
                        typer.echo(f"\n📋 Full detailed report available in: {output}")
                    else:
                        typer.echo("✅ No security threats detected")
                else:
                    # Display report to console
                    typer.echo("\n" + report_content)
                    
            except Exception as e:
                # Fallback to simple output if reporting fails
                typer.echo(f"\n⚠️  Report generation failed: {str(e)}")
                if verbose:
                    import traceback
                    typer.echo(traceback.format_exc(), err=True)
                    
                # Show basic summary as fallback
                if detection_result.total_findings > 0:
                    typer.echo(f"\n🚨 {detection_result.total_findings} security findings detected")
                    typer.echo("📋 Use --verbose for detailed finding information")
                else:
                    typer.echo("\n✅ No security threats detected")
                    
        else:
            typer.echo("\n⚠️  No successfully parsed entries available for detection analysis")
            
    except IngestionError as e:
        typer.echo(f"❌ File ingestion failed: {str(e)}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"❌ Unexpected error during analysis: {str(e)}", err=True)
        if verbose:
            import traceback
            typer.echo(traceback.format_exc(), err=True)
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show LogLens version information."""
    from . import __version__
    typer.echo(f"LogLens version: {__version__}")


def main() -> None:
    """Entry point for the CLI application."""
    app()


if __name__ == "__main__":
    main() 